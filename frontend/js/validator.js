/**
 * CyberLens Client-Side IOC Hygiene & Detection Utility
 */

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$/;
const MD5_REGEX = /^[a-fA-F0-9]{32}$/;
const SHA1_REGEX = /^[a-fA-F0-9]{40}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;
const DOMAIN_REGEX = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$/;
const URL_REGEX = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;

export const ClientValidator = {
  /**
   * Remove defanging syntax in real time
   */
  sanitize(raw) {
    if (!raw) return "";
    let clean = raw.trim();

    // Strip enclosing brackets/quotes
    if ((clean.startsWith("<") && clean.endsWith(">")) ||
        (clean.startsWith('"') && clean.endsWith('"')) ||
        (clean.startsWith("'") && clean.endsWith("'"))) {
      clean = clean.slice(1, -1).trim();
    }

    // Protocol defangs
    clean = clean.replace(/^hxxps?:\/\//i, (m) => m.toLowerCase().includes("s") ? "https://" : "http://");

    // Dot and colon defangs: [.] -> .  [:] -> :
    clean = clean.replace(/\[\.\]|\(\.\)|\{\.\}/g, ".");
    clean = clean.replace(/\[\:\]|\(\:\)/g, ":");

    return clean;
  },

  /**
   * Fast client classification
   */
  detectType(input) {
    const clean = this.sanitize(input);
    if (!clean) return null;

    if (URL_REGEX.test(clean)) return "URL";
    if (IPV4_REGEX.test(clean)) return "IPv4";
    if (SHA256_REGEX.test(clean)) return "SHA-256";
    if (SHA1_REGEX.test(clean)) return "SHA-1";
    if (MD5_REGEX.test(clean)) return "MD5";
    if (clean.includes(":") && IPV6_REGEX.test(clean)) return "IPv6";
    if (DOMAIN_REGEX.test(clean)) return "Domain";

    return null;
  },
};
