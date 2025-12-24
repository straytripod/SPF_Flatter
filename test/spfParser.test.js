// test/spfParser.test.js
const { expect } = require('chai');
const sinon = require('sinon');

describe('parseSpf', () => {
    const { parseSpf } = require('../spfParser');

    it('should parse a simple SPF record with v=spf1 and all mechanism', () => {
        const spfRecord = "v=spf1 ~all";
        const expected = [
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '~', type: 'all', value: 'all' }
        ];
        expect(parseSpf(spfRecord)).to.deep.equal(expected);
    });

    it('should parse an SPF record with include mechanism', () => {
        const spfRecord = "v=spf1 include:_spf.google.com ~all";
        const expected = [
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'include', value: '_spf.google.com' },
            { qualifier: '~', type: 'all', value: 'all' }
        ];
        expect(parseSpf(spfRecord)).to.deep.equal(expected);
    });

    it('should parse an SPF record with ip4 mechanism', () => {
        const spfRecord = "v=spf1 ip4:192.0.2.1/24 -all";
        const expected = [
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '192.0.2.1/24' },
            { qualifier: '-', type: 'all', value: 'all' }
        ];
        expect(parseSpf(spfRecord)).to.deep.equal(expected);
    });

    it('should handle different qualifiers', () => {
        const spfRecord = "v=spf1 +a ?mx -ptr ~all";
        const expected = [
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'a', value: '' }, // 'a' mechanism without value
            { qualifier: '?', type: 'mx', value: '' }, // 'mx' mechanism without value
            { qualifier: '-', type: 'ptr', value: '' }, // 'ptr' mechanism without value
            { qualifier: '~', type: 'all', value: 'all' }
        ];
        expect(parseSpf(spfRecord)).to.deep.equal(expected);
    });

    it('should handle mechanisms with no explicit value', () => {
        const spfRecord = "v=spf1 a mx -all";
        const expected = [
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'a', value: '' },
            { qualifier: '+', type: 'mx', value: '' },
            { qualifier: '-', type: 'all', value: 'all' }
        ];
        expect(parseSpf(spfRecord)).to.deep.equal(expected);
    });

    it('should throw an error for invalid input', () => {
        expect(() => parseSpf(null)).to.throw("Invalid SPF record provided. Must be a non-empty string.");
        expect(() => parseSpf(undefined)).to.throw("Invalid SPF record provided. Must be a non-empty string.");
        expect(() => parseSpf("")).to.throw("Invalid SPF record provided. Must be a non-empty string.");
    });

    it('should parse a complex SPF record', () => {
        const spfRecord = "v=spf1 include:_spf.example.com include:spf.protection.outlook.com ip4:192.168.1.1/32 ip6:2001:0db8::/32 a mx ptr exists:%{i}.spf.example.org ~all";
        const expected = [
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'include', value: '_spf.example.com' },
            { qualifier: '+', type: 'include', value: 'spf.protection.outlook.com' },
            { qualifier: '+', type: 'ip4', value: '192.168.1.1/32' },
            { qualifier: '+', type: 'ip6', value: '2001:0db8::/32' },
            { qualifier: '+', type: 'a', value: '' },
            { qualifier: '+', type: 'mx', value: '' },
            { qualifier: '+', type: 'ptr', value: '' },
            { qualifier: '+', type: 'exists', value: '%{i}.spf.example.org' },
            { qualifier: '~', type: 'all', value: 'all' }
        ];
        expect(parseSpf(spfRecord)).to.deep.equal(expected);
    });
});

describe('flattenSpf', () => {
    let spfParser;
    let mockResolver;
    let originalDnsResolver;
    let resolveTxtStub;

    beforeEach(() => {
        // Unload the module to ensure we can re-import it with mocks
        delete require.cache[require.resolve('../spfParser')];
        spfParser = require('../spfParser');
        
        // Store the original resolver and set up the mock
        originalDnsResolver = spfParser.dnsResolver;
        resolveTxtStub = sinon.stub();
        mockResolver = { resolveTxt: resolveTxtStub };
        spfParser.setDnsResolver(mockResolver);
    });

    afterEach(() => {
        // Restore the original resolver
        spfParser.setDnsResolver(originalDnsResolver);
        // Unload the module again to clean up
        delete require.cache[require.resolve('../spfParser')];
    });

    it('should return the original parsed SPF if no includes or redirects', async () => {
        const parsedSpf = spfParser.parseSpf("v=spf1 ip4:1.2.3.4 ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '1.2.3.4' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.notCalled).to.be.true;
    });

    it('should flatten a simple include mechanism', async () => {
        resolveTxtStub.withArgs('included.com').resolves([['v=spf1 ip4:5.6.7.8 -all']]);

        const parsedSpf = spfParser.parseSpf("v=spf1 include:included.com ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '5.6.7.8' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledOnceWith('included.com')).to.be.true;
    });

    it('should flatten a redirect mechanism', async () => {
        resolveTxtStub.withArgs('redirected.com').resolves([['v=spf1 ip4:9.10.11.12 ?all']]);

        const parsedSpf = spfParser.parseSpf("v=spf1 redirect=redirected.com");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '9.10.11.12' },
            { qualifier: '?', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledOnceWith('redirected.com')).to.be.true;
    });

    it('should handle nested includes', async () => {
        resolveTxtStub.withArgs('level1.com').resolves([['v=spf1 include:level2.com']]);
        resolveTxtStub.withArgs('level2.com').resolves([['v=spf1 ip4:10.0.0.1 ~all']]);

        const parsedSpf = spfParser.parseSpf("v=spf1 include:level1.com -all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");

        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '10.0.0.1' },
            { qualifier: '-', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledWith('level1.com')).to.be.true;
        expect(resolveTxtStub.calledWith('level2.com')).to.be.true;
        expect(resolveTxtStub.callCount).to.equal(2);
    });

    it('should handle multiple includes at the same level', async () => {
        resolveTxtStub.withArgs('inc1.com').resolves([['v=spf1 ip4:1.1.1.1']]);
        resolveTxtStub.withArgs('inc2.com').resolves([['v=spf1 ip4:2.2.2.2']]);

        const parsedSpf = spfParser.parseSpf("v=spf1 include:inc1.com include:inc2.com ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");

        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '1.1.1.1' },
            { qualifier: '+', type: 'ip4', value: '2.2.2.2' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledWith('inc1.com')).to.be.true;
        expect(resolveTxtStub.calledWith('inc2.com')).to.be.true;
        expect(resolveTxtStub.callCount).to.equal(2);
    });

    it('should respect the DNS lookup limit', async () => {
        // Set up 10 stubs for lookup, the 11th should trigger the limit warning
        for (let i = 0; i < 10; i++) {
            resolveTxtStub.withArgs(`domain${i}.com`).resolves([[`v=spf1 ip4:1.1.1.${i}`]]);
        }
        resolveTxtStub.withArgs('overlimit.com').resolves([['v=spf1 ip4:9.9.9.9']]); // This should not be resolved

        const includes = Array.from({ length: 10 }, (_, i) => `include:domain${i}.com`).join(' ');
        const spfRecord = `v=spf1 ${includes} include:overlimit.com ~all`; // 10 includes plus one more
        const parsedSpf = spfParser.parseSpf(spfRecord);
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        
        expect(flattened).to.have.length(12); // v=spf1 + 10 ip4s + ~all
        // Check if ip4s from domain0.com to domain9.com are present
        for (let i = 0; i < 10; i++) {
            expect(flattened).to.deep.include({ qualifier: '+', type: 'ip4', value: `1.1.1.${i}` });
        }
        // The last include (overlimit.com) should not have resulted in an ip4
        expect(flattened).to.not.deep.include({ qualifier: '+', type: 'ip4', value: '9.9.9.9' });
        expect(resolveTxtStub.callCount).to.equal(10); // Only 10 lookups should occur
    });

    it('should handle empty or non-spf TXT records gracefully', async () => {
        resolveTxtStub.withArgs('empty.com').resolves([['some other txt record']]);
        resolveTxtStub.withArgs('no-record.com').resolves([]);

        const parsedSpf = spfParser.parseSpf("v=spf1 include:empty.com include:no-record.com ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");

        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledWith('empty.com')).to.be.true;
        expect(resolveTxtStub.calledWith('no-record.com')).to.be.true;
        expect(resolveTxtStub.callCount).to.equal(2);
    });

    it('should prioritize the outermost all mechanism', async () => {
        resolveTxtStub.withArgs('included.com').resolves([['v=spf1 ip4:5.6.7.8 -all']]);

        // Outer record has ~all, included has -all. ~all should win.
        const parsedSpf = spfParser.parseSpf("v=spf1 include:included.com ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '5.6.7.8' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
    });

    it('should handle all mechanism from included records if no outermost all is present', async () => {
        resolveTxtStub.withArgs('included.com').resolves([['v=spf1 ip4:5.6.7.8 -all']]);

        // No 'all' in the main record, so the one from included.com should be kept.
        const parsedSpf = spfParser.parseSpf("v=spf1 include:included.com");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '5.6.7.8' },
            { qualifier: '-', type: 'all', value: 'all' }
        ]);
    });

    it('should remove duplicate mechanisms', async () => {
        resolveTxtStub.withArgs('included.com').resolves([['v=spf1 ip4:1.2.3.4']]);

        const parsedSpf = spfParser.parseSpf("v=spf1 ip4:1.2.3.4 include:included.com ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '+', type: 'ip4', value: '1.2.3.4' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledOnce).to.be.true;
    });

    it('should handle DNS lookup errors gracefully', async () => {
        resolveTxtStub.withArgs('error.com').rejects(new Error('DNS lookup failed'));
        
        const parsedSpf = spfParser.parseSpf("v=spf1 include:error.com ~all");
        const flattened = await spfParser.flattenSpf(parsedSpf, "example.com");
        
        expect(flattened).to.deep.equal([
            { qualifier: '+', type: 'v', value: 'spf1' },
            { qualifier: '~', type: 'all', value: 'all' }
        ]);
        expect(resolveTxtStub.calledOnce).to.be.true;
    });
});