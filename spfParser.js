// spfParser.js
// This file will contain functions for parsing SPF records.
const { Resolver } = require('dns').promises;

let dnsResolver = new Resolver();
dnsResolver.setServers(['8.8.8.8', '1.1.1.1']); // Use Google's and Cloudflare's DNS

function setDnsResolver(resolver) {
    dnsResolver = resolver;
}

const MAX_DNS_LOOKUPS = 10; // SPF RFC specifies a limit of 10 DNS lookups

/**
 * Resolves SPF TXT records for a given hostname.
 * @param {string} hostname The hostname to query.
 * @param {number} currentDnsLookups The current count of DNS lookups.
 * @returns {Promise<{spfRecords: string[], newLookupCount: number}>} A promise that resolves to an array of SPF record strings and the updated lookup count.
 */
async function resolveSpfTxtRecord(hostname, currentDnsLookups) {
    if (currentDnsLookups >= MAX_DNS_LOOKUPS) {
        console.warn(`Maximum DNS lookup limit (${MAX_DNS_LOOKUPS}) exceeded for ${hostname}.`);
        return { spfRecords: [], newLookupCount: currentDnsLookups };
    }
    try {
        const records = await dnsResolver.resolveTxt(hostname);
        const spfRecords = records
            .map(record => record.join(''))
            .filter(record => record.startsWith('v=spf1'));
        return { spfRecords, newLookupCount: currentDnsLookups + 1 };
    } catch (error) {
        // Handle NXDOMAIN (no such domain) or other DNS errors gracefully
        if (error.code === 'ENOTFOUND' || error.code === 'ESERVFAIL' || error.code === 'ENODATA') {
            console.warn(`DNS lookup for ${hostname} failed: ${error.message}. Skipping this record.`);
        } else {
            console.error(`DNS TXT lookup failed for ${hostname}:`, error.message);
        }
        return { spfRecords: [], newLookupCount: currentDnsLookups + 1 };
    }
}

/**
 * Parses an SPF record string into a structured representation.
 * @param {string} spfRecord The SPF record string.
 * @returns {Array<Object>} An array of SPF mechanism objects.
 */
function parseSpf(spfRecord) {
    if (!spfRecord || typeof spfRecord !== 'string') {
        throw new Error("Invalid SPF record provided. Must be a non-empty string.");
    }

    const mechanisms = spfRecord.split(/\s+/).filter(part => part.length > 0);
    const parsedMechanisms = [];

    mechanisms.forEach(mechanismString => {
        let qualifier = '+'; // Default qualifier
        let type = mechanismString;
        let value = '';

        // Check for qualifier
        if (['+', '-', '~', '?'].includes(mechanismString[0])) {
            qualifier = mechanismString[0];
            type = mechanismString.substring(1);
        }

        const parts = type.split(':');
        if (parts.length > 1) {
            type = parts[0];
            value = parts.slice(1).join(':');
        } else {
            // Handle mechanisms like 'all' which might not have a ':'
            // or 'v=spf1' or 'redirect=' which use '='
            if (type.includes('=')) {
                const partsWithEquals = type.split('=');
                type = partsWithEquals[0];
                value = partsWithEquals[1];
            } else if (type === 'all') { // Handle 'all' mechanism
                value = 'all'; // Value is implicitly 'all'
            }
        }
        
        parsedMechanisms.push({ qualifier, type, value });
    });

    return parsedMechanisms;
}

/**
 * Recursively flattens an SPF record by resolving 'include' and 'redirect' mechanisms.
 * @param {Array<Object>} parsedSpf The parsed SPF record (from parseSpf function).
 * @param {string} domain The domain for which the SPF record is being flattened.
 * @param {number} currentDnsLookups The current count of DNS lookups.
 * @returns {Promise<{flattenedMechanisms: Array<Object>, newLookupCount: number}>} A promise that resolves to the flattened SPF mechanisms and the updated lookup count.
 */
async function recursiveFlattenSpf(parsedSpf, domain, currentDnsLookups) {
    let flattenedMechanisms = [];
    let dnsLookups = currentDnsLookups;
    let finalAllMechanism = null;

    for (const mechanism of parsedSpf) {
        if (mechanism.type === 'v') {
            // 'v=spf1' should only appear once at the beginning of the final flattened record
            // We'll add it back at the very end of the main flattenSpf function.
            continue;
        }

        if (mechanism.type === 'redirect') {
            const hostnameToLookup = mechanism.value;
            const { spfRecords: resolvedSpfRecords, newLookupCount } = await resolveSpfTxtRecord(hostnameToLookup, dnsLookups);
            dnsLookups = newLookupCount;

            if (resolvedSpfRecords.length > 0) {
                // For redirect, we take the *first* SPF record found and stop processing the current record
                const subParsedSpf = parseSpf(resolvedSpfRecords[0]);
                const { flattenedMechanisms: subFlattened, newLookupCount: subNewLookupCount } =
                    await recursiveFlattenSpf(subParsedSpf, hostnameToLookup, dnsLookups);
                dnsLookups = subNewLookupCount;
                return { flattenedMechanisms: subFlattened, newLookupCount: dnsLookups };
            }
            return { flattenedMechanisms: [], newLookupCount: dnsLookups }; // If redirect target has no SPF, return empty
        } else if (mechanism.type === 'include') {
            const hostnameToLookup = mechanism.value;
            const { spfRecords: resolvedSpfRecords, newLookupCount } = await resolveSpfTxtRecord(hostnameToLookup, dnsLookups);
            dnsLookups = newLookupCount;

            for (const record of resolvedSpfRecords) {
                const subParsedSpf = parseSpf(record);
                const { flattenedMechanisms: subFlattened, newLookupCount: subNewLookupCount } =
                    await recursiveFlattenSpf(subParsedSpf, hostnameToLookup, dnsLookups);
                dnsLookups = subNewLookupCount;
                flattenedMechanisms.push(...subFlattened.filter(m => m.type !== 'v')); // Exclude 'v=spf1' from included records
            }
        } else if (mechanism.type === 'all') {
            finalAllMechanism = mechanism; // Keep track of the last 'all'
        } else {
            flattenedMechanisms.push(mechanism);
        }
    }

    // Remove duplicates (except for 'all' which is handled separately)
    let uniqueMechanisms = [];
    const seen = new Set();
    for (const mech of flattenedMechanisms) {
        const mechString = JSON.stringify(mech);
        if (!seen.has(mechString)) {
            uniqueMechanisms.push(mech);
            seen.add(mechString);
        }
    }

    // Add the final 'all' mechanism if it exists, ensuring it's the very last
    if (finalAllMechanism) {
        // Remove any other 'all' mechanisms if they were added earlier from includes
        const filteredUniqueMechanisms = uniqueMechanisms.filter(m => m.type !== 'all');
        uniqueMechanisms = [...filteredUniqueMechanisms, finalAllMechanism];
    }
    
    return { flattenedMechanisms: uniqueMechanisms, newLookupCount: dnsLookups };
}

/**
 * Flattens an SPF record by resolving 'include' and 'redirect' mechanisms.
 * @param {Array<Object>} parsedSpf The parsed SPF record (from parseSpf function).
 * @param {string} domain The domain for which the SPF record is being flattened.
 * @returns {Promise<Array<Object>>} A promise that resolves to the flattened SPF mechanisms.
 */
async function flattenSpf(parsedSpf, domain) {
    const initialDnsLookups = 0;
    const { flattenedMechanisms, newLookupCount } = await recursiveFlattenSpf(parsedSpf, domain, initialDnsLookups);
    
    // Add the 'v=spf1' mechanism back at the beginning of the flattened record
    const vSpf1 = parsedSpf.find(mech => mech.type === 'v' && mech.value === 'spf1');
    return vSpf1 ? [vSpf1, ...flattenedMechanisms] : flattenedMechanisms;
}

module.exports = {
    parseSpf,
    flattenSpf,
    resolveSpfTxtRecord,
    setDnsResolver,
    dnsResolver,
    recursiveFlattenSpf,
};
