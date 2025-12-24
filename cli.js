#!/usr/bin/env node
const { parseSpf, flattenSpf, resolveSpfTxtRecord } = require('./spfParser');
const { verifySpf } = require('./spf-validator');
const fs = require('fs').promises;

async function main() {
    const args = process.argv.slice(2);
    const verifyIndex = args.indexOf('--verify');
    let domain, outputFile;

    if (verifyIndex > -1) {
        args.splice(verifyIndex, 1);
        if (args.length < 1) {
            console.error('Usage: spf-flatting --verify <domain>');
            process.exit(1);
        }
        domain = args[0];
        await runVerification(domain);
    } else {
        if (args.length < 1) {
            console.error('Usage: spf-flatting <domain> [output-file]');
            process.exit(1);
        }
        domain = args[0];
        outputFile = args[1];
        await runFlattening(domain, outputFile);
    }
}

async function runVerification(domain) {
    try {
        console.log(`Verifying SPF record for ${domain}...`);
        const results = await verifySpf(domain);

        console.log('\n--- SPF Verification Results ---');
        console.log(`Domain: ${domain}`);
        console.log(`SPF Record Found: ${results.hasSpfRecord}`);
        
        if (results.hasSpfRecord) {
            console.log(`DNS Lookups: ${results.dnsLookups}`);
            console.log(`Lookup Limit Exceeded: ${results.lookupLimitExceeded}`);
        }

        if (results.errors.length > 0) {
            console.log('\nErrors:');
            results.errors.forEach(err => console.log(`- ${err}`));
        }

        if (results.syntaxErrors.length > 0) {
            console.log('\nSyntax Errors:');
            results.syntaxErrors.forEach(err => console.log(`- ${err}`));
        }

        if (results.errors.length === 0 && results.syntaxErrors.length === 0) {
            console.log('\nSPF record appears to be valid.');
        }

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

async function runFlattening(domain, outputFile) {
    try {
        console.log(`Fetching SPF record for ${domain}...`);
        const { spfRecords } = await resolveSpfTxtRecord(domain, 0);

        if (spfRecords.length === 0) {
            console.error(`No SPF record found for ${domain}.`);
            process.exit(1);
        }

        const spfRecordString = spfRecords[0];
        if (spfRecords.length > 1) {
            console.warn(`Multiple SPF records found for ${domain}. Using the first one: ${spfRecordString}`);
        }

        console.log(`Found SPF record: ${spfRecordString}`);

        console.log(`\nParsing SPF record for domain: ${domain}`);
        const parsed = parseSpf(spfRecordString);
        console.log('Parsed SPF:', JSON.stringify(parsed, null, 2));

        console.log('\nFlattening SPF record...');
        const flattened = await flattenSpf(parsed, domain);
        
        const flattenedSpfString = flattened.map(mech => {
            let output = mech.qualifier === '+' ? '' : mech.qualifier;
            output += mech.type;
            if (mech.value && mech.value !== 'all') {
                output += ':' + mech.value;
            }
            return output;
        }).join(' ');

        if (outputFile) {
            await fs.writeFile(outputFile, flattenedSpfString);
            console.log(`\nFlattened SPF record written to: ${outputFile}`);
        } else {
            console.log('\nFlattened SPF:');
            console.log(flattenedSpfString);
        }

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

main();
