// PhishGuard — URL phishing analyzer
// Author: Abenezer | MIT License | 2026
//
// Checks for things like IP-based URLs, suspicious TLDs, brand spoofing,
// homoglyphs, entropy spikes, keyword stuffing, and obfuscation tricks.

'use strict';

/* THREAT INTELLIGENCE DATA SETS*/

/** Well-known brands that are commonly impersonated */
const BRANDS = [
  'paypal', 'apple', 'amazon', 'google', 'microsoft', 'facebook', 'instagram',
  'twitter', 'netflix', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'hsbc', 'barclays', 'lloyds', 'santander', 'rbc', 'td', 'scotiabank',
  'ebay', 'alibaba', 'aliexpress', 'dropbox', 'linkedin', 'snapchat', 'tiktok',
  'spotify', 'youtube', 'twitch', 'discord', 'reddit', 'pinterest', 'tumblr',
  'outlook', 'office365', 'onedrive', 'icloud', 'gmail', 'yahoo', 'hotmail',
  'live', 'docusign', 'zoom', 'webex', 'teams', 'slack', 'salesforce',
  'adobe', 'intuit', 'turbotax', 'quickbooks', 'coinbase', 'binance',
  'kraken', 'blockchain', 'metamask', 'opensea', 'steam', 'epic', 'roblox',
  'blizzard', 'battlenet', 'playstation', 'xbox', 'nintendo', 'dhl', 'fedex',
  'ups', 'usps', 'royalmail', 'currys', 'bestbuy', 'walmart', 'target',
  'costco', 'ikea', 'zara', 'h&m', 'shein', 'asos', 'etsy', 'shopify',
  'stripe', 'square', 'venmo', 'cashapp', 'wise', 'revolut', 'monzo',
  'n26', 'transferwise', 'ing', 'bnpparibas', 'creditagricole', 'societegeneral',
  'americanexpress', 'visa', 'mastercard', 'discover', 'capitalone', 'synchrony',
];

/** High-risk TLDs frequently used in phishing campaigns */
const SUSPICIOUS_TLDS = new Set([
  'ru', 'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'party',
  'date', 'racing', 'faith', 'review', 'loan', 'cricket', 'science', 'win',
  'bid', 'trade', 'accountant', 'download', 'stream', 'gdn', 'icu', 'buzz',
  'cyou', 'monster', 'rest', 'bar', 'quest', 'lat', 'fun', 'sbs',
]);

/** URL shortener domains */
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'cutt.ly',
  'rb.gy', 'rebrand.ly', 'short.io', 'bl.ink', 'surl.li', 'clk.sh',
  'shorte.st', 'ouo.io', 'bc.vc', 'adfoc.us', 'linktr.ee',
]);

/** Homoglyph / lookalike character map (Unicode spoofing + alphanum) */
const HOMOGLYPHS = {
  a: ['а', '@', '4', 'α'],   // Cyrillic а
  b: ['б', '6', 'ß'],
  c: ['с', 'ς'],            // Cyrillic с
  e: ['е', 'з', '3', '€', 'ε'], // Cyrillic е
  g: ['9', 'ğ'],
  i: ['1', 'l', '!', 'ı', 'і'], // Unicode dotless i, Cyrillic і
  l: ['1', '|', 'ı'],
  m: ['rn', 'ṁ'],
  n: ['и', 'η'],
  o: ['0', 'о', 'ο', 'σ'],    // Cyrillic о, Greek ο
  p: ['р'],                // Cyrillic р
  q: ['9'],
  s: ['5', '$', 'ѕ'],
  u: ['v', 'υ'],
  v: ['u', 'ν'],
  w: ['vv', 'ω'],
  x: ['×'],
  y: ['у', 'ý'],            // Cyrillic у
  z: ['2'],
};

/** Build a reverse map: glyph → canonical letter */
const GLYPH_TO_CANON = new Map();
for (const [canon, glyphs] of Object.entries(HOMOGLYPHS)) {
  for (const g of glyphs) GLYPH_TO_CANON.set(g, canon);
}

/** Suspicious keywords for path/query analysis */
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'logon', 'account', 'secure', 'security',
  'verify', 'verification', 'confirm', 'update', 'billing', 'payment', 'invoice',
  'refund', 'alert', 'suspend', 'unlock', 'recover', 'password', 'credential',
  'banking', 'wallet', 'auth', 'authenticate', '2fa', 'otp', 'ebayisapi',
  'webscr', 'cmd=_login', 'validate', 'support', 'helpdesk', 'customer-service',
];

/** Regex: IPv4 in host */
const RE_IPv4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/** Regex: IPv6 brackets */
const RE_IPv6 = /^\[.*\]$/;

/** Regex: Hex-encoded IP (e.g., 0xC0A80001) */
const RE_HEX_IP = /^0x[0-9a-f]{8}$/i;

/** Regex: Octal IP or dword IP */
const RE_OCT_IP = /^(0\d+\.){3}0\d+$/;

/** Regex: Punycode label */
const RE_PUNYCODE = /xn--/i;

/** Regex: Data or JS scheme */
const RE_DANGEROUS_SCHEME = /^(data:|javascript:|vbscript:|about:)/i;

/** Regex: URL-encoded characters that could obfuscate */
const RE_URL_ENCODE = /%[0-9a-f]{2}/gi;

/** Regex: Double encoding */
const RE_DOUBLE_ENCODE = /%25[0-9a-f]{2}/gi;

/** Regex: @-trick in URL (user:pass@domain) */
const RE_AT_TRICK = /@/;


// --- core helpers ---

// adds https:// if the user didn't type a scheme
function normalizeUrl(raw) {
  const trimmed = raw.trim();
  if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(trimmed)) return trimmed;
  // Try with https:// prefix
  return 'https://' + trimmed;
}

// wraps new URL() so it doesn't blow up on bad input
function safeParse(urlStr) {
  try { return new URL(urlStr); } catch { return null; }
}

// Shannon entropy — high values suggest randomly generated/DGA domains
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum - p * Math.log2(p);
  }, 0);
}

// swaps lookalike chars (е, 0, rn) back to their ASCII equivalents
function deHomoglyph(str) {
  let out = '';
  for (const ch of str.toLowerCase()) {
    out += GLYPH_TO_CANON.get(ch) ?? ch;
  }
  return out;
}

// edit distance — used for typosquat detection
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

// checks if a domain label is impersonating a known brand (exact contains or close typo)
function findBrandImpersonation(domainLabel) {
  const cleaned = deHomoglyph(domainLabel);
  let best = null;
  for (const brand of BRANDS) {
    // Exact match — not suspicious per se (it IS the brand)
    if (cleaned === brand) continue;

    // Contains brand but isn't it
    if (cleaned.includes(brand) && cleaned !== brand) {
      return { brand, distance: 0, type: 'contains' };
    }

    // Levenshtein typosquat (within edit distance 2 for longer brands)
    const maxAllowed = brand.length > 6 ? 2 : 1;
    const dist = levenshtein(cleaned, brand);
    if (dist <= maxAllowed && dist > 0) {
      if (!best || dist < best.distance) best = { brand, distance: dist, type: 'typosquat' };
    }
  }
  return best;
}

// counts %xx sequences in the raw URL
function urlEncodeCount(str) {
  return (str.match(RE_URL_ENCODE) || []).length;
}

// rough TLD reputation — high/medium/low
function tldRisk(tld) {
  const t = tld.replace(/^\./, '').toLowerCase();
  if (SUSPICIOUS_TLDS.has(t)) return 'high';
  const lowMedium = new Set([
    'info', 'biz', 'name', 'mobi', 'pro', 'tel', 'asia', 'pw', 'cc', 'ws',
    'click', 'link', 'site', 'online', 'store', 'website', 'space', 'tech',
    'live', 'host', 'press', 'guru', 'ninja',
  ]);
  if (lowMedium.has(t)) return 'medium';
  return 'low';
}


// --- main analysis ---

// runs all the checks and returns a score + findings for a given URL
function analyzeUrl(raw) {
  const normalized = normalizeUrl(raw);
  const parsed = safeParse(normalized);
  const originalHasScheme = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(raw.trim());

  /* ── Parse failure ── */
  if (!parsed) {
    return {
      valid: false,
      error: 'Could not parse this as a valid URL. Check the format and try again.',
      score: 0, risk: 'SAFE', indicators: [], findings: [], parsed: {},
    };
  }

  const indicators = [];
  const findings = [];
  let riskTotal = 0;

  const protocol = parsed.protocol.toLowerCase().replace(/:$/, '');
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;
  const fullUrl = parsed.href;
  const tld = hostname.includes('.') ? '.' + hostname.split('.').pop() : '';

  /* helper to push indicator */
  const addIndicator = (name, value, status, score, description) => {
    indicators.push({ name, value, status, score, description });
    riskTotal += score;
  };

  /* helper to push finding */
  const addFinding = (type, icon, title, detail) => {
    findings.push({ type, icon, title, detail });
  };


  // 1. catch dangerous schemes like data: or javascript:
  if (RE_DANGEROUS_SCHEME.test(raw.trim())) {
    addIndicator('Scheme', raw.substring(0, 20) + '…', 'danger', 40,
      'Dangerous URI scheme that can execute code in the browser.');
    addFinding('flag-error', '💀', 'Dangerous Scheme', 'Uses a code-execution scheme (data:/javascript:)');
  }

  // 2. HTTPS check
  if (protocol === 'https') {
    addIndicator('Protocol', 'HTTPS ✓', 'ok', 0, 'Connection is encrypted.');
  } else if (protocol === 'http') {
    const httpScore = 12;
    addIndicator('Protocol', 'HTTP — No Encryption', 'warn', httpScore,
      'Site does not use HTTPS. Credentials sent over HTTP can be intercepted.');
    addFinding('flag-warn', '🔓', 'No HTTPS', 'Connection is unencrypted; data can be intercepted');
    riskTotal += 0; // already added
  } else {
    addIndicator('Protocol', protocol, 'warn', 8, `Unusual URL scheme: ${protocol}`);
  }

  // 3. IP-based URLs — legit services almost never use raw IPs
  const isIPv4 = RE_IPv4.test(hostname);
  const isIPv6 = RE_IPv6.test(hostname);
  const isHexIP = RE_HEX_IP.test(hostname);
  const isOctIP = RE_OCT_IP.test(hostname);

  if (isIPv4 || isHexIP || isOctIP) {
    addIndicator('Host Type', `IP Address: ${hostname}`, 'danger', 30,
      'Legitimate services rarely use raw IP addresses. Phishing kits often do.');
    addFinding('flag-error', '🔢', 'IP-Based URL', 'Host is a raw IP address, not a domain name');
  } else if (isIPv6) {
    addIndicator('Host Type', `IPv6: ${hostname}`, 'danger', 28,
      'IPv6 literal addresses in URLs are uncommon and suspicious.');
    addFinding('flag-error', '🔢', 'IP-Based URL (IPv6)', 'Host uses a raw IPv6 literal');
  } else {
    addIndicator('Host Type', 'Domain Name ✓', 'ok', 0, 'URL uses a proper domain name.');
  }

  // 4. punycode / IDN — can make аmazon.com look like amazon.com
  if (RE_PUNYCODE.test(hostname)) {
    addIndicator('IDN / Punycode', hostname, 'danger', 25,
      'Punycode domains can visually spoof legitimate domains using lookalike Unicode characters (e.g., аmazon.com).');
    addFinding('flag-error', '🌐', 'Punycode / IDN Domain', 'May visually impersonate a legitimate domain');
  } else {
    addIndicator('IDN / Punycode', 'Not detected ✓', 'ok', 0, 'No Punycode encoding found.');
  }

  // 5. URL shorteners hide the real destination
  const isShortener = SHORTENERS.has(hostname) ||
    [...SHORTENERS].some(s => hostname.endsWith('.' + s));

  if (isShortener) {
    addIndicator('URL Shortener', hostname, 'warn', 18,
      'URL shorteners hide the real destination. Phishers use them to mask malicious URLs.');
    addFinding('flag-warn', '🔗', 'URL Shortener Detected', 'Destination is masked — cannot verify the real URL');
  } else {
    addIndicator('URL Shortener', 'Not detected ✓', 'ok', 0, 'Not a known URL shortener.');
  }

  // 6. too many subdomains is a red flag (e.g. secure.paypal.verify.update.evil.com)
  const labels = hostname.split('.');
  const subdomainCount = Math.max(0, labels.length - 2);

  if (subdomainCount >= 4) {
    addIndicator('Subdomain Depth', `${subdomainCount} subdomains`, 'danger', 22,
      'Excessive subdomains (e.g., secure.paypal.verify.update.evil.com) are used to confuse users.');
    addFinding('flag-error', '🧩', 'Excessive Subdomains', `${subdomainCount} subdomain levels detected`);
  } else if (subdomainCount === 3) {
    addIndicator('Subdomain Depth', `${subdomainCount} subdomains`, 'warn', 12,
      '3+ subdomains is uncommon for legitimate services.');
    addFinding('flag-caution', '🧩', 'Deep Subdomain Structure', `${subdomainCount} subdomain levels`);
  } else {
    addIndicator('Subdomain Depth', `${subdomainCount} subdomain(s) ✓`, 'ok', 0,
      'Normal subdomain depth.');
  }

  // 7. TLD reputation
  const tldRiskLevel = tldRisk(tld);
  if (tldRiskLevel === 'high') {
    addIndicator('TLD Reputation', tld || '(none)', 'danger', 20,
      `The TLD "${tld}" is heavily associated with phishing and spam domains.`);
    addFinding('flag-error', '⚠️', 'High-Risk TLD', `"${tld}" is a common phishing top-level domain`);
  } else if (tldRiskLevel === 'medium') {
    addIndicator('TLD Reputation', tld, 'warn', 8,
      `The TLD "${tld}" has elevated risk; not inherently malicious but uncommon.`);
    addFinding('flag-caution', '⚠️', 'Uncommon TLD', `"${tld}" has moderate risk`);
  } else {
    addIndicator('TLD Reputation', tld || '(none)', 'ok', 0, 'TLD has normal reputation.');
  }

  // 8. brand impersonation — check each label against known brands
  let brandMatch = null;
  for (const label of labels) {
    const m = findBrandImpersonation(label);
    if (m) { brandMatch = { ...m, inLabel: label }; break; }
  }

  if (brandMatch) {
    const detail = brandMatch.type === 'contains'
      ? `Domain label "${brandMatch.inLabel}" contains "${brandMatch.brand}" spelling`
      : `"${brandMatch.inLabel}" is ${brandMatch.distance} edit(s) from "${brandMatch.brand}"`;
    const score = brandMatch.type === 'contains' ? 25 : 30;
    addIndicator('Brand Impersonation', `Likely "${brandMatch.brand}"`, 'danger', score, detail);
    addFinding('flag-error', '🎭', 'Brand Impersonation', detail);
  } else {
    addIndicator('Brand Impersonation', 'None detected ✓', 'ok', 0,
      'No known brand spoofing found in domain labels.');
  }

  // 9. domain entropy — high randomness = likely machine-generated
  const sld = labels.length >= 2 ? labels[labels.length - 2] : hostname;
  const entropy = shannonEntropy(sld);
  const entropyStr = entropy.toFixed(2);

  if (entropy > 4.0) {
    addIndicator('Domain Entropy', `${entropyStr} bits/char (very high)`, 'danger', 20,
      'Extremely high entropy suggests a Domain Generation Algorithm (DGA) or randomly generated phishing domain.');
    addFinding('flag-error', '🎲', 'High Domain Randomness', `Entropy ${entropyStr} — possible DGA domain`);
  } else if (entropy > 3.5) {
    addIndicator('Domain Entropy', `${entropyStr} bits/char (elevated)`, 'warn', 10,
      'Elevated randomness in the domain name. Legitimate branded domains tend to have lower entropy.');
    addFinding('flag-caution', '🎲', 'Elevated Domain Entropy', `Entropy ${entropyStr} bit/char`);
  } else {
    addIndicator('Domain Entropy', `${entropyStr} bits/char ✓`, 'ok', 0,
      'Domain appears to be a human-readable word — low randomness.');
  }

  // 10. homoglyphs in the hostname itself
  const hasHomoglyph = [...hostname].some(ch => GLYPH_TO_CANON.has(ch));
  if (hasHomoglyph) {
    addIndicator('Homoglyphs', 'Detected in domain', 'danger', 28,
      'Domain contains Unicode look-alike characters used to visually spoof legitimate domains.');
    addFinding('flag-error', '🔤', 'Homoglyph Characters', 'Domain uses visually similar Unicode chars to spoof a brand');
  } else {
    addIndicator('Homoglyphs', 'None detected ✓', 'ok', 0, 'No homoglyph substitutions found.');
  }

  // 11. suspicious keywords in path/query (login, verify, billing, etc.)
  const fullPathQuery = (pathname + parsed.search + parsed.hash).toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => fullPathQuery.includes(kw));

  if (matchedKeywords.length >= 3) {
    addIndicator('Suspicious Keywords', matchedKeywords.slice(0, 5).join(', '), 'danger', 18,
      'Multiple credential/payment related keywords in path suggest a phishing landing page.');
    addFinding('flag-error', '🔑', 'Multiple Suspicious Keywords', `Found: ${matchedKeywords.slice(0, 4).join(', ')}`);
  } else if (matchedKeywords.length > 0) {
    addIndicator('Suspicious Keywords', matchedKeywords.join(', '), 'warn', 6 * matchedKeywords.length,
      'Keywords associated with credential harvesting or account takeover.');
    addFinding('flag-caution', '🔑', 'Suspicious Keywords in Path', `Found: ${matchedKeywords.join(', ')}`);
  } else {
    addIndicator('Suspicious Keywords', 'None found ✓', 'ok', 0,
      'No suspicious credential/payment keywords detected.');
  }

  // 12. URL length — very long URLs are often obfuscated phishing links
  const urlLen = fullUrl.length;
  if (urlLen > 200) {
    addIndicator('URL Length', `${urlLen} chars (very long)`, 'danger', 14,
      'Abnormally long URLs are used to hide the true domain or confuse users/filters.');
    addFinding('flag-warn', '📏', 'Very Long URL', `${urlLen} characters — may be designed to obscure real destination`);
  } else if (urlLen > 100) {
    addIndicator('URL Length', `${urlLen} chars (long)`, 'warn', 5,
      'Long URL; review carefully to ensure the domain is what you expect.');
  } else {
    addIndicator('URL Length', `${urlLen} chars ✓`, 'ok', 0, 'URL length is within normal range.');
  }

  // 13. obfuscation tricks — double encoding, @-trick
  const rawForObfusc = raw.trim();
  const encodeCount = urlEncodeCount(rawForObfusc);
  const hasDoubleEnc = RE_DOUBLE_ENCODE.test(rawForObfusc);
  // @-trick: only scan the authority part (scheme + host, before the first '/') 
  // to avoid false positives on paths containing @ (e.g., social media handles)
  const authorityPart = rawForObfusc.replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//, '').split('/')[0];
  const hasAtTrick = RE_AT_TRICK.test(authorityPart);

  if (hasDoubleEnc) {
    addIndicator('Double Encoding', 'Detected', 'danger', 22,
      'Double URL-encoding (%25xx) is used to bypass security filters.');
    addFinding('flag-error', '🔒', 'Double URL Encoding', 'Possible filter evasion via double %xx encoding');
  }
  if (hasAtTrick) {
    addIndicator('@-Trick', 'Detected', 'danger', 25,
      'The @ character in a URL causes browsers to ignore everything before it as a username — used to disguise the real host.');
    addFinding('flag-error', '🎯', '@-Trick Detected', 'The real destination is after the @ sign');
  }
  if (encodeCount > 5 && !hasDoubleEnc) {
    addIndicator('URL Encoding', `${encodeCount} encoded chars`, 'warn', 8,
      'Excessive URL encoding may be used to obfuscate the path from filters.');
    addFinding('flag-caution', '🔢', 'Heavy URL Encoding', `${encodeCount} encoded characters in URL`);
  }
  if (!hasDoubleEnc && !hasAtTrick && encodeCount <= 5) {
    addIndicator('Obfuscation', 'None detected ✓', 'ok', 0, 'No obfuscation techniques detected.');
  }

  // 14. excessive hyphens in domain (e.g. paypal-secure-login-update.com)
  const hyphenCount = (sld.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    addIndicator('Hyphen Count', `${hyphenCount} hyphens in SLD`, 'danger', 16,
      'Phishing domains frequently use many hyphens (e.g., paypal-secure-login-update.com) to pack keywords.');
    addFinding('flag-error', '➖', 'Excessive Hyphens', `${hyphenCount} hyphens in domain name`);
  } else if (hyphenCount === 2) {
    addIndicator('Hyphen Count', `${hyphenCount} hyphens`, 'warn', 6,
      'Multiple hyphens in domain name — moderately suspicious.');
    addFinding('flag-caution', '➖', 'Multiple Hyphens', `${hyphenCount} hyphens in domain`);
  } else {
    addIndicator('Hyphen Count', `${hyphenCount} ✓`, 'ok', 0, 'Normal hyphen usage.');
  }

  // cap score at 100 and convert to risk label
  const score = Math.min(100, Math.round(riskTotal));

  let risk;
  if (score >= 70) risk = 'CRITICAL';
  else if (score >= 50) risk = 'HIGH';
  else if (score >= 30) risk = 'MEDIUM';
  else if (score >= 12) risk = 'LOW';
  else risk = 'SAFE';

  /* positives summary */
  const okCount = indicators.filter(i => i.status === 'ok').length;
  if (okCount > 0 && risk === 'SAFE') {
    addFinding('flag-ok', '✅', 'No Threats Detected', `${okCount} indicators checked — all clear`);
  }

  return {
    valid: true, score, risk,
    indicators,
    findings,
    parsed: {
      scheme: parsed.protocol,
      host: parsed.host,
      hostname,
      pathname,
      search: parsed.search,
      hash: parsed.hash,
      tld,
      sld,
      subdomainCount,
      fullUrl: parsed.href,
    },
  };
}


// --- UI rendering ---

const CIRCUMFERENCE = 2 * Math.PI * 52; // 326.73

function getRiskClass(risk) {
  return { SAFE: 'risk-safe', LOW: 'risk-low', MEDIUM: 'risk-medium', HIGH: 'risk-high', CRITICAL: 'risk-critical' }[risk];
}

function getRingColor(risk) {
  return { SAFE: '#10b981', LOW: '#22d3ee', MEDIUM: '#f59e0b', HIGH: '#f97316', CRITICAL: '#ef4444' }[risk];
}

function getVerdictText(risk) {
  return {
    SAFE: { icon: '🛡️', label: 'SAFE', desc: 'This URL appears legitimate. No significant phishing indicators were found.' },
    LOW: { icon: '✅', label: 'LOW RISK', desc: 'Minor anomalies detected. Exercise general caution but likely safe.' },
    MEDIUM: { icon: '⚠️', label: 'MEDIUM RISK', desc: 'Several suspicious indicators found. Verify this URL before proceeding.' },
    HIGH: { icon: '🚨', label: 'HIGH RISK', desc: 'Multiple strong phishing signals detected. Avoid entering credentials on this site.' },
    CRITICAL: { icon: '🔴', label: 'CRITICAL', desc: 'This URL exhibits hallmarks of a phishing attack. Do NOT proceed.' },
  }[risk];
}

function getRecommendation(risk, result) {
  const { icon, label } = getVerdictText(risk);
  const recs = {
    SAFE: {
      cls: 'rec-safe', icon: '🛡️', header: 'This URL appears safe',
      body: 'No major phishing indicators detected. Always remain vigilant — no automated tool is 100% accurate. When in doubt, navigate directly to the official website.'
    },
    LOW: {
      cls: 'rec-safe', icon: '💡', header: 'Low risk — proceed with care',
      body: 'Minor indicators detected. Consider:<ul><li>Validate the domain is exactly as expected</li><li>Avoid entering sensitive information if you did not initiate the request</li></ul>'
    },
    MEDIUM: {
      cls: 'rec-warn', icon: '⚠️', header: 'Proceed with caution',
      body: 'Suspicious signals were found. Recommended actions:<ul><li>Do not enter passwords or payment info</li><li>Navigate to the official site by typing the URL directly</li><li>Check if you were expecting this link</li></ul>'
    },
    HIGH: {
      cls: 'rec-danger', icon: '🚨', header: 'Do not proceed',
      body: 'Strong phishing indicators detected. Recommended actions:<ul><li>Close this page immediately</li><li>Do not click any links or download files</li><li>Report to your IT/security team or browser\'s safe browsing report</li><li>Change passwords if you already submitted information</li></ul>'
    },
    CRITICAL: {
      cls: 'rec-danger', icon: '💀', header: 'Critical threat — Do NOT visit this URL',
      body: 'This URL has characteristics of a confirmed phishing or malware delivery site. Actions to take:<ul><li>Do NOT open this URL in any browser</li><li>Report to cyber crime authorities (e.g., CISA, Action Fraud, NCSC)</li><li>Warn others who may have received this link</li><li>If already visited: change all passwords and monitor accounts</li></ul>'
    },
  };
  return recs[risk];
}

function renderUrlBreakdown(parsedData) {
  const { scheme, hostname, pathname, search, hash, sld, tld, subdomainCount } = parsedData;
  const isSecure = scheme === 'https:';

  return `
    <div class="url-bd-label">URL Analysis</div>
    <div class="url-bd-row">
      <span class="url-bd-key">Scheme</span>
      <span class="url-bd-part ${isSecure ? 'url-bd-scheme secure' : 'url-bd-scheme'}">${scheme}//</span>
      <span class="url-bd-key">Host</span>
      <span class="url-bd-part url-bd-domain">${hostname}</span>
      ${pathname && pathname !== '/' ? `<span class="url-bd-key">Path</span><span class="url-bd-part url-bd-path">${pathname}${search}${hash}</span>` : ''}
    </div>
    <div class="url-bd-row" style="margin-top:6px; gap:14px;">
      <span class="url-bd-key">SLD: <span style="color:#6366f1">${sld}</span></span>
      <span class="url-bd-key">TLD: <span style="color:#64748b">${tld}</span></span>
      <span class="url-bd-key">Subdomains: <span style="color:#64748b">${subdomainCount}</span></span>
    </div>
  `;
}

function renderFindings(findings) {
  if (!findings.length) return '';
  return findings.map((f, i) => `
    <div class="finding-card ${f.type}" style="animation-delay:${0.05 + i * 0.06}s">
      <div class="finding-icon">${f.icon}</div>
      <div class="finding-title">${f.title}</div>
      <div class="finding-detail">${f.detail}</div>
    </div>
  `).join('');
}

function renderIndicatorTable(indicators) {
  return indicators.map(ind => `
    <div class="indicator-row">
      <div class="ind-name">${ind.name}</div>
      <div class="ind-value">${ind.value}</div>
      <div class="ind-status ${ind.status}"></div>
    </div>
  `).join('');
}

function renderRecommendation(rec) {
  return `
    <div class="rec-header">
      <span class="rec-icon">${rec.icon}</span>
      ${rec.header}
    </div>
    <div class="rec-body">${rec.body}</div>
  `;
}

function animateScore(targetScore, ringEl, numEl) {
  const duration = 1200;
  const start = performance.now();
  const offset = CIRCUMFERENCE - (targetScore / 100) * CIRCUMFERENCE;

  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 4);
    const current = Math.round(ease * targetScore);
    numEl.textContent = current;
    ringEl.style.strokeDashoffset = CIRCUMFERENCE - (ease * targetScore / 100) * CIRCUMFERENCE;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function displayResults(result, rawUrl) {
  const panel = document.getElementById('resultsPanel');
  const riskCls = getRiskClass(result.risk);

  // URL Breakdown
  document.getElementById('urlBreakdown').innerHTML = renderUrlBreakdown(result.parsed);

  // Verdict row
  const verdictRow = panel.querySelector('.verdict-row');
  verdictRow.className = `verdict-row ${riskCls}`;

  const { icon, label, desc } = getVerdictText(result.risk);
  document.getElementById('verdictBadge').innerHTML = `${icon} ${label}`;
  document.getElementById('verdictDesc').textContent = desc;

  // Animate ring + score
  const ringFill = document.getElementById('ringFill');
  const scoreNum = document.getElementById('scoreNum');
  ringFill.style.stroke = getRingColor(result.risk);
  animateScore(result.score, ringFill, scoreNum);

  // Threat meter
  document.getElementById('threatBarFill').style.width = result.score + '%';

  // Findings
  document.getElementById('findingsGrid').innerHTML = renderFindings(result.findings);

  // Indicator table
  document.getElementById('indicatorTable').innerHTML = renderIndicatorTable(result.indicators);

  // Recommendation
  const rec = getRecommendation(result.risk, result);
  const recBox = document.getElementById('recommendation');
  recBox.className = `recommendation-box glass ${rec.cls}`;
  recBox.innerHTML = renderRecommendation(rec);

  // Show panel
  panel.classList.remove('hidden');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showError(msg) {
  const panel = document.getElementById('resultsPanel');
  panel.innerHTML = `
    <div class="glass" style="border-radius:14px;padding:28px 24px;text-align:center;border-color:rgba(239,68,68,0.3);">
      <div style="font-size:2rem;margin-bottom:12px">❌</div>
      <div style="font-weight:700;color:#ef4444;margin-bottom:8px">Invalid URL</div>
      <div style="color:#64748b;font-size:0.9rem">${msg}</div>
    </div>
  `;
  panel.classList.remove('hidden');
}


// --- event wiring ---

document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('urlInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const clearBtn = document.getElementById('clearBtn');
  const resetBtn = document.getElementById('resetBtn');
  const resultsPanel = document.getElementById('resultsPanel');

  // Show/hide clear button
  urlInput.addEventListener('input', () => {
    clearBtn.style.display = urlInput.value.length > 0 ? 'flex' : 'none';
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus();
    resultsPanel.classList.add('hidden');
  });

  // Example chips
  document.querySelectorAll('.example-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.dataset.url;
      urlInput.value = url;
      clearBtn.style.display = 'flex';
      triggerAnalysis(url);
    });
  });

  // Enter key
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && urlInput.value.trim()) triggerAnalysis(urlInput.value.trim());
  });

  // Analyze button
  analyzeBtn.addEventListener('click', () => {
    const val = urlInput.value.trim();
    if (val) triggerAnalysis(val);
  });

  // Reset button
  resetBtn.addEventListener('click', () => {
    resultsPanel.classList.add('hidden');
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  function triggerAnalysis(url) {
    // UI loading state
    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;

    // Simulate brief async (real analysis is sync, but UX feels intentional)
    setTimeout(() => {
      const result = analyzeUrl(url);
      analyzeBtn.classList.remove('loading');
      analyzeBtn.disabled = false;

      if (!result.valid) {
        showError(result.error);
      } else {
        displayResults(result, url);
      }
    }, 600);
  }

  // Auto-focus
  urlInput.focus();
});
