// spf-validator.js
// This file will contain functions for validating SPF records.
const { resolveSpfTxtRecord, parseSpf, recursiveFlattenSpf } = require('./spfParser');

const MAX_DNS_LOOKUPS = 10;

/**
 * Validates the syntax of a parsed SPF record.
 * @param {Array<Object>} parsedSpf The parsed SPF record.
 * @returns {Array<string>} An array of syntax error messages.
 */
function validateSpfSyntax(parsedSpf) {
    const errors = [];
    const mechanisms = parsedSpf.map(m => m.type);

    // Check for v=spf1 at the beginning
    if (mechanisms[0] !== 'v' || parsedSpf[0].value !== 'spf1') {
        errors.push("The SPF record must start with 'v=spf1'.");
    }

    // Check for invalid characters
    const allowedChars = /^[a-zA-Z0-9-._=:\/+\?~ ]*$/;
    const rawSpf = parsedSpf.map(m => (m.qualifier !== '+' ? m.qualifier : '') + m.type + (m.value ? `:${m.value}` : '')).join(' ');
    if (!allowedChars.test(rawSpf)) {
        errors.push("The SPF record contains invalid characters.");
    }

    // Check for multiple 'redirect' or 'all'
    if (mechanisms.filter(m => m === 'redirect').length > 1) {
        errors.push("Multiple 'redirect' mechanisms found. Only one is allowed.");
    }
    if (mechanisms.filter(m => m === 'all').length > 1) {
        errors.push("Multiple 'all' mechanisms found. Only one is allowed.");
    }

    // Check for 'all' mechanism at the end
    if (mechanisms.includes('all') && mechanisms[mechanisms.length - 1] !== 'all') {
        errors.push("The 'all' mechanism must be the last mechanism in the SPF record.");
    }

    // Check if 'redirect' is used with other mechanisms
    if (mechanisms.includes('redirect') && mechanisms.length > 2) { // > 2 to account for v=spf1 and redirect
        errors.push("The 'redirect' mechanism cannot be used with other mechanisms.");
    }

    return errors;
}


/**
 * Verifies if an SPF record meets SPF standards.
 * @param {string} domain The domain to verify.
 * @returns {Promise<Object>} A promise that resolves to an object containing verification results.
 */
async function verifySpf(domain) {
    const results = {
        hasSpfRecord: false,
        dnsLookups: 0,
        lookupLimitExceeded: false,
        errors: [],
        syntaxErrors: [],
    };

    const { spfRecords, newLookupCount } = await resolveSpfTxtRecord(domain, 0);
    results.dnsLookups = newLookupCount;

    if (spfRecords.length > 0) {
        results.hasSpfRecord = true;
    } else {
        results.errors.push(`No SPF record found for ${domain}.`);
        return results;
    }

    if (spfRecords.length > 1) {
        results.errors.push(`Multiple SPF records found for ${domain}. Only one is allowed.`);
    }

    const parsedSpf = parseSpf(spfRecords[0]);
    results.syntaxErrors = validateSpfSyntax(parsedSpf);

    const { newLookupCount: finalLookupCount } = await recursiveFlattenSpf(parsedSpf, domain, results.dnsLookups);

    results.dnsLookups = finalLookupCount;

    if (results.dnsLookups > MAX_DNS_LOOKUPS) {
        results.lookupLimitExceeded = true;
        results.errors.push(`SPF record for ${domain} exceeds the 10 DNS lookup limit. Found ${results.dnsLookups} lookups.`);
    }

    return results;
}

module.exports = {
    verifySpf,
};
