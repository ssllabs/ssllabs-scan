
# Note: This schema designed for PostgreSQL.

CREATE TABLE domains (
    domainName               VARCHAR(254) NOT NULL,
    -- The domain name, with the "www" prefix (where such prefix exists).
    
    domainDepth              INTEGER NOT NULL CHECK (domainDepth > 0),
    -- How far is the doimain name from its TLD? For example,
    -- example.com would have a depth of 1; webmail.example.com a depth of 2.
    -- The "www" prefix is ignored, if it exists.
            
    ipAddress                VARCHAR(16) NOT NULL,
    -- The IP address the domain name resolved to at the time of testing
    
    port                     INTEGER NOT NULL,
    -- Always 443.
    
    
    -- Time-related fields
    
    checkTime                TIMESTAMP NOT NULL,
    -- The time when the test began.
    
    handshakeDuration        INTEGER CHECK (handshakeDuration > 0) NOT NULL,
    -- Unused.
    
    validationDuration       INTEGER CHECK (validationDuration >= 0) NOT NULL, 
    -- Unused.    
    
    requestDuration          INTEGER CHECK (requestDuration > 0) NOT NULL,
    -- The time, in milliseconds, it took the server to respond to the
    -- request we issued on an established SSL connection.    
     
    configCheckDuration      INTEGER CHECK (configCheckDuration > 0) NOT NULL,
    -- The time, in milliseconds, it took us to execute all other tests (those
    -- performed using the custom SSL inspection library).
    
    
    -- Certificate information
    
    subject                  TEXT NOT NULL,
    -- X500 principal in RFC 2253 format. Encoded.
    
    subjectCommonName        TEXT,
    -- Common names extracted from the subject, if any. If multiple common names
    -- are present, they are separated with spaces. Encoded.
    
    subjectCountry           VARCHAR(32) NOT NULL,
    -- The country name extracted from the subject. The field should contain a
    -- two-letter country code, but many are invalid. Contains "Unknown" if unknown.
    -- Encoded.
    
    altNames                 TEXT NOT NULL,
    -- Space-separated alternative names from the certificates. Encoded.
    
    altNameCount             INTEGER NOT NULL,
    -- How many alternative names are there in the certificate?
    
    isWildcard               BOOLEAN NOT NULL,
    -- Is the common name a wildcard?
    
    prefixSupport            BOOLEAN NOT NULL,
    -- Does the certificate support both prefix and prefix-less domain name?       
    
    issuer                   TEXT NOT NULL,
    -- X500 issuer in RFC 2253 format. Encoded.
    
    issuerCommonName         TEXT,
    -- Issuer common name. Encoded.
    
    notAfter                 TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Certificate expiration date.
    
    notBefore                TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Certificate activation date.
        
    signatureAlg             VARCHAR(64),
    -- Hash algorithm, e.g., MD5, SHA, etc. Encoded.
    
    keyAlg                   VARCHAR(64) NOT NULL,
    -- Public key algorithm: RSA, DSA, or EC. Encoded.
        
    keySize                  INTEGER NOT NULL CHECK (keySize > 0),
    -- Key size, in the units specific to the algorithm (also see keyStrength,
    -- which contains the strength of the key in RSA bits).
    
    validationType           CHAR(1) NOT NULL,
    -- Values: Domain-validated (D), Organisation-validated (O), Extended Validation (E)
    -- ONLY IMPLEMENTED FOR EXTENDED VALIDATION; OTHER VALUES NOT RELIABLE 
    
    isScg                    INTEGER NOT NULL,
    -- Support for server-gated cryptography, as below:
    --   0 - none
    --   1 - Netscape SGC
    --   2 - Microsoft SGC
    --   3 - Netscape & Microsoft SGC
    
    revocationInfo           INTEGER NOT NULL,
    -- bit 0: 1 - CRL
    -- bit 1: 2 - OCSP 
        
    chainLength              INTEGER NOT NULL CHECK (chainLength > 0),                    
    -- The length of the chain sent by the server.
    
    chainSize                INTEGER NOT NULL CHECK (chainSize > 0),
    -- Chain size, in bytes.
    
    chainIssuers             TEXT NOT NULL,
    -- A list of all chain issuers, separated with newlines. Encoded.
    
    chainData                TEXT NOT NULL,
    -- Contains raw chain data. Base64-encoded.
    
    isTrusted                INTEGER NOT NULL,
    -- a certificate is valid if it is trusted, if the time is right, and
    -- if the common name matches the expected hostname. The value of this
    -- field is a combination of the following bits:
    --   1 - no chain of trust
    --   2 - not before
    --   4 - not after
    --   8 - hostname mismatch
    --  16 - revoked
    --  32 - bad common name
    --  64 - self-signed      
    
    
    -- Protocol support
    
    supports_SSL2_hello      INTEGER NOT NULL,
    -- 0 - no support
    -- 1 - responded with SSLv2
    -- 2 - responded with SSLv3+
    
    supports_SSL_2_0         BOOLEAN NOT NULL,
    supports_SSL_3_0         BOOLEAN NOT NULL,
    supports_TLS_1_0         BOOLEAN NOT NULL,
    supports_TLS_1_1         BOOLEAN NOT NULL,
    supports_TLS_1_2         BOOLEAN NOT NULL,       
    
    
    -- Cipher suite information 
    
    suites                   TEXT NOT NULL,
    -- A space-separated list of supported cipher suites (hexadecimal numbers).
    
    suiteCount               INTEGER NOT NULL,
    -- How many supported cipher suites are there?
    
    suitesInOrder            BOOLEAN,
    -- TRUE if server has cipher suite preference, in which
    -- case the suites will be listed in the preferred order.
    -- FALSE if there's no preference, or NULL if we could
    -- not determine the preference.
    
    supports_no_bits         BOOLEAN NOT NULL,
    supports_low_bits        BOOLEAN NOT NULL,
    supports_128_bits        BOOLEAN NOT NULL,
    supports_256_bits        BOOLEAN NOT NULL,
    
    em_ssl2                  BOOLEAN NOT NULL,
    em_40_bits               BOOLEAN NOT NULL,
    em_56_bits               BOOLEAN NOT NULL,
    em_64_bits               BOOLEAN NOT NULL,           
    -- The above fields indicate if error messages are used to refuse to
    -- respond to HTTP requests over weak protocols or suites. The tests
    -- currently only know how to detect the error messagees from
    -- NetScaler and Microsoft.
    
    serverSignature          VARCHAR(254),
    -- HTTP Server signature; can be NULL. Encoded.
    
    grade                    INTEGER CHECK ((grade >= 0) AND (grade <= 100)) NOT NULL,
    -- SSL Labs numerical grade, according to the 2009c rating guide.
    
    gradeLetter              CHAR(1) NOT NULL,
    -- SSL Labs letter grade (A-F), according to the 2009c rating guide.
    

    -- Special tests
    
    debianFlawed             BOOLEAN,
    -- Has a low-entropy certificate been detected?    
    
    sessionResumption        INTEGER NOT NULL,
    -- 0 - empty session IDs
    -- 1 - session IDs provided, but not reused
    -- 2 - enabled
    
    stsResponseHeader        TEXT,
    -- Strict-Transport-Security response header, if seen.
    
    renegSupport             INTEGER,
    -- bit 0: insecure client-initiated renegotiation supported
    -- bit 1: secure renegotiation supported
    -- bit 2: secure client-initiated renegotiation supported
    -- bit 3: server requires secure renegotiation support
    
    toleranceMinorLow        INTEGER NOT NULL,
    -- The protocol version we received in response to 
    -- attempting to negotiate version 0x0304. Contains -1
    -- if connection failed without response.
    
    toleranceMinorHigh       INTEGER NOT NULL,
    -- The protocol version we received in response to 
    -- attempting to negotiate version 0x0399. Contains -1
    -- if connection failed without response.
    
    toleranceMajorHigh       INTEGER NOT NULL,    
    -- The protocol version we received in response to 
    -- attempting to negotiate version 0x0499. Contains -1
    -- if connection failed without response.
    
    pciReady                 BOOLEAN NOT NULL,
    -- TRUE if the certificate is trusted, the key size is 1024 or better,
    -- and only strong protocols (no SSLv2) and cipher suites (>= 128 bits,
    -- no ADH, or export ones) are supported.
    
    fipsReady                BOOLEAN NOT NULL,
    -- As above, but only allows the use of FIPS-approved cipher suites
    -- along with TLS v1.0 and better.
    
    chainIssues              INTEGER NOT NULL,
    -- bit 0 - unused
    -- bit 1 - incomplete chain (set only when we were able to build a trusted
    --         chain by adding missing intermediate certificates from external sources)
    -- bit 2 - chain contains unrelated certificates (i.e., certificates that are not
    --         part of the same chain)
    -- bit 3 - the certificates form a chain (trusted or not), but the order is incorrect
    -- bit 4 - contains root certificate (not set for self-signed leafs)
    -- bit 5 - the certificates form a chain, but we could not validate it (if the leaf
    --         was trusted, that means that we built a different chain we trusted).
    
    fixedChainLength         INTEGER NOT NULL,
    -- Unused.
    
    fixedChainSize           INTEGER NOT NULL,
    -- Unused.
    
    trustAnchor              TEXT,
    -- X500 trust anchor in RFC 2253 format. Encoded.
    
    engineVersion            VARCHAR(64) NOT NULL,
    -- Assessment engine version number.
    
    criteriaVersion          VARCHAR(64) NOT NULL,
    -- Version number of the criteria used for grading.
    
    crlUris                  TEXT NOT NULL,
    -- Space-separated CRL endpoints. Can be empty.
    
    ocspUris                 TEXT NOT NULL,
    -- Space-separated OCSP endpoints. Can be empty.
    
    vulnBEAST                BOOLEAN,
    -- Is the server vulnerable to the BEAST attack?
    
    stsMaxAge                INTEGER,
    -- Maximum age used in HSTS. Available only when HSTS is present.
    
    stsIncludeSubdomains	   BOOLEAN,
    -- Whether the includeSubDomains feature was enabled in
    -- the HSTS response. Available only when HSTS is present.
    
    pkpResponseHeader		     TEXT,
    -- Public-Key-Pins response header, if seen.
    
    surveyId                 VARCHAR(32) NOT NULL,
    -- Used to identify the assessments that are part of the same round.
    
    compression              INTEGER,
    -- bit 0: DEFLATE
    
    npnSupport				       BOOLEAN,
    
    npnProtocols             TEXT,
    -- Space-separated list of supported NPN protocols
    
    sessionTickets           INTEGER,
    -- bit 0 - set if session tickets are supported
    -- bit 1 (not implemented) - faulty
    -- bit 2 - set if the server is intolerant to the extension
    
    ocspStapling             BOOLEAN,
    -- True if OCSP stapling support was detected
    
    sniRequired              BOOLEAN,
    -- True if SNI is required for the hostname
    
    httpStatusCode           INTEGER,
    -- The status code we received on the main HTTP request. Can
    -- be NULL if the request was not successful.
    
    httpForwarding           VARCHAR(254),
    -- Contains the URL to which the server being tested redirects to
    -- (redirections to URLs within the same hostname are excluded).
    
    keyStrength              INTEGER CHECK (keyStrength > 0),
    -- Key size, converted to an RSA equivalent when Elliptic Curves are used.
    
    -- This table has a design flaw, in that it assumes a server
    -- can have only one certificate chain. But some servers may have
    -- several, for example, one for each RSA, DSA, and ECDSA. This
    -- is very rare, but will increase in the future as ECDSA certificates
    -- become more popular.
    --
    -- To fix the issue, the schema will need to be significantly changed. Until
    -- then, I am adding a couple of fields to track the usage of multiple
    -- certificate chains.
    
    chainCount               INTEGER CHECK (chainCount > 0),
    -- How many different certificate chains were seen?
    
    chainData2               TEXT,
    -- Contains raw chain data. Base64-encoded.
    
    chainData3               TEXT,
    -- Contains raw chain data. Base64-encoded.
    
    rg2009b_grade            INTEGER CHECK ((rg2009b_grade >= 0) AND (rg2009b_grade <= 100)),
    -- SSL Labs numerical grade, according to the 2009b rating guide.
    
    rg2009b_letter           CHAR(1) CHECK (rg2009b_letter IN ('A', 'B', 'C', 'D', 'E', 'F')),
    -- SSL Labs letter grade (A-F), according to the 2009b rating guide.
    
    beastSuites              VARCHAR(128),
    -- Cipher suites obtained when attempting the protocols vulnerable to the BEAST attack.
    -- Example "300:35; 301:35". Protocol number first, followed by the suite number. Both hex.
    
    protocolIntolerance      INTEGER,
    -- bit 0: TLS 1.0
    -- bit 1: TLS 1.1
    -- bit 2: TLS 1.2
    
    miscIntolerance          INTEGER,
    -- bit 0: extension intolerance
    -- bit 1: long handshake intolerance
    -- bit 2: long handshake intolerance workaround success
    
    sims                     TEXT,
    -- simulation results (e.g., "34 (0 1 301 c011); 35 (0 1 303 c028)"
    -- The first number is the client ID. Then follows the error code (zero
    -- means no error), how many connection attempts were made, and the negotiated
    -- protocol and cipher suite (the last two are hexadecimal).
    
    forwardSecrecy           INTEGER,
    -- bit 0: none/some
    -- bit 1: modern browsers
    -- bit 2: robust (ECDHE + DHE)
    
    rc4                      INTEGER,
    -- bit 0: RC4 present among the suites
    -- bit 1: RC4 seen used by grade 0 clients

    hasWarnings              BOOLEAN,

    isExceptional            BOOLEAN,

    heartbeat                BOOLEAN,

    heartbleed               BOOLEAN,

    cve_2014_0224            INTEGER,
    -- One of the following values are possible:
    --     -1: the test failed
    --      0: unknown
    --      1: not vulnerable
    --      2: vulnerable but not exploitable (OpenSSL 0.9.x and 1.0.0; false positives possible)
    --      3: vulnerable and exploitable (OpenSSL 1.0.1+)
    
    PRIMARY KEY (domainName, surveyId)
);

CREATE INDEX domains_ipAddress ON domains(ipAddress);
 