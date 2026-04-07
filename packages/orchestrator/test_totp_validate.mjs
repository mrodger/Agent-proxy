import speakeasy from "speakeasy";

const secret = "JAUU66JJGZHFG3DUKJHHIYSJFIZEISTCIB3GMYSAO5JXK4S3G4XA";

// Generate code at current time
const code = speakeasy.totp({
  secret: secret,
  encoding: "base32",
});

// Verify with various windows
for (let w = 0; w <= 2; w++) {
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token: code,
    window: w
  });
  console.log(`Code ${code} with window=${w}: ${verified}`);
}
