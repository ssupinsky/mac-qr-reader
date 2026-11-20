// aia-probe — test-only. Reads a DER leaf certificate on stdin and evaluates it with
// network fetching allowed (SSL + OCSP-required revocation policy). If trustd is reachable,
// it fetches the certificate's AIA caIssuers / OCSP / CRL URLs on our behalf — a network
// channel out of the helper sandbox. test/native/sandbox.test.mjs runs this under
// native/qr-decode.sb with a local HTTP listener and asserts that no request arrives.
// Build: swiftc -O -o <out> test/native/probes/aia-probe.swift
import Foundation
import Security

let der = FileHandle.standardInput.readDataToEndOfFile()
guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { print("bad-cert"); exit(2) }
var trust: SecTrust?
let ssl = SecPolicyCreateSSL(true, "probe.example" as CFString)
SecTrustCreateWithCertificates(cert, ssl, &trust)
SecTrustSetNetworkFetchAllowed(trust!, true)
let rev = SecPolicyCreateRevocation(kSecRevocationOCSPMethod | kSecRevocationRequirePositiveResponse)!
SecTrustSetPolicies(trust!, [ssl, rev] as CFArray)
var err: CFError?
let ok = SecTrustEvaluateWithError(trust!, &err)
print("evaluated ok=\(ok)")
