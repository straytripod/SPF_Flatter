# SPF Flatting
SPF flattening is the process of replacing domain names in an SPF (Sender Policy Framework) DNS record with their actual IP addresses to reduce the DNS lookups a system has to do. The SPF standard's limit lookups to 10. By reducing the lookups to below 10 we can avoid email rejections. While flattening the records solves the lookup limit issue by making records static and shorter, manual flattening increases maintenance costs as IPs change. This often requires ongoing manual updates to prevent deliverablity issues. Using an SPF management service a better long-term choice for complex SPF records containing many references.

# SPF Flattener

This is a Node.js command-line tool for parsing, flattening, and verifying SPF (Sender Policy Framework) records.

## Installation

To use the tool, you need to have Node.js and npm installed. Clone the repository and install the dependencies:

Ubuntu Linux:
```bash
sudo apt install nodejs npm -y
```

Fedora Linux:
```bash
sudo dnf install nodejs -y
```

Clone project:
```bash
git clone <repository-url>
cd SPF_Flatting
npm install
```

## Usage

To use the tool, run `cli.js` with the domain you want to process.

### Direct Execution

```bash
node cli.js <domain> [output-file]
node cli.js --verify <domain>
```

**Arguments:**

*   `<domain>`: The domain for which the SPF record should be fetched and processed.
*   `[output-file]`: (Optional) The path to a file where the flattened SPF record will be written. If not provided, the output will be printed to the console.
*   `--verify`: (Optional) Use this flag to verify the SPF record against SPF standards.

**Example (Flattening):**

```bash
node cli.js google.com
node cli.js protonmail.com flattened_spf.txt
```

**Example (Verification):**

```bash
node cli.js --verify google.com
```

### Global Installation (Optional)

You can link the package to make the `spf-flatting` command available globally:

```bash
npm link
```

If you encounter permission errors, you may need to run this command with `sudo`:

```bash
sudo npm link
```

Once linked, you can use the tool like this:

```bash
spf-flatting <domain> [output-file]
spf-flatting --verify <domain>
```

**Example (Flattening):**

```bash
spf-flatting google.com
spf-flatting protonmail.com flattened_spf.txt
```

**Example (Verification):**

```bash
spf-flatting --verify google.com
```

## How It Works

The tool performs the following steps:

1.  **Fetches the SPF Record**: It performs a DNS TXT lookup to find the `v=spf1` record for the specified domain. It uses reliable public DNS servers to ensure accurate resolution.

2.  **Parses the SPF Record**: It takes the fetched SPF record string and parses it into a structured format, identifying all the mechanisms (`v`, `ip4`, `ip6`, `include`, `redirect`, `a`, `mx`, `ptr`, `exists`, `all`) and their qualifiers (`+`, `-`, `~`, `?`).

3.  **Flattens the SPF Record**: It recursively resolves `include` and `redirect` mechanisms by performing further DNS lookups. It adheres to the SPF RFC's limit of 10 DNS lookups to prevent infinite loops and excessive lookups.

4.  **Outputs the Flattened Record**: The final result is a single, flattened SPF record string with all the resolved mechanisms, ready to be used.

## SPF Verification Feature

The `--verify` flag allows you to check if an SPF record adheres to common SPF standards and best practices.

**Checks performed:**

*   **Presence of SPF Record**: Ensures a `v=spf1` TXT record exists for the domain.
*   **Multiple SPF Records**: Warns if multiple SPF records are found (only one is allowed per domain).
*   **DNS Lookup Limit**: Verifies that the record (after flattening) does not exceed the 10 DNS lookup limit specified by the SPF RFC.
*   **Syntax Validation**: Performs basic syntax checks, including:
    *   Starts with `v=spf1`.
    *   Contains only allowed characters.
    *   No multiple `redirect` or `all` mechanisms.
    *   `all` mechanism is the last mechanism if present.
    *   `redirect` mechanism is used exclusively (not with other mechanisms).

**Example Output:**

```
Verifying SPF record for google.com...

--- SPF Verification Results ---
Domain: google.com
SPF Record Found: true
DNS Lookups: 4
Lookup Limit Exceeded: false

SPF record appears to be valid.
```

## Testing

The project includes a suite of unit tests for the parsing and flattening logic. To run the tests:

```bash
npm test
```
