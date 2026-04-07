const speakeasy = require('speakeasy');

const secret = 'JAUU66JJGZHFG3DUKJHHIYSJFIZEISTCIB3GMYSAO5JXK4S3G4XA';
const code = speakeasy.totp({
  secret: secret,
  encoding: 'base32',
  window: 1
});

console.log('Generated TOTP:', code);

const verified = speakeasy.totp.verify({
  secret: secret,
  encoding: 'base32',
  token: code,
  window: 1
});

console.log('Verified:', verified);
