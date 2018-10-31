/*
 * This software is licensed under the MIT License.
 *
 * Copyright Fedor Indutny, 2015.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

'use strict';

var ocsp = require('ocsp');
var rfc2560 = require('asn1.js-rfc2560');
var rfc3280 = require('asn1.js-rfc3280');
var crypto = require('crypto');

module.exports = function verify(options, cb) {
  var req = options.request;
  var issuer;
  var res;

  function done(err) {
    process.nextTick(function() {
      cb(err, res);
    });
  }

  try {
    issuer = req.issuer ||
        rfc3280.Certificate.decode(
            ocsp.utils.toDER(options.issuer, 'CERTIFICATE'), 'der');

    res = ocsp.utils.parseResponse(options.response);
  } catch (e) {
    return done(e);
  }

  // Verify signature using CAs Public Key
  // TODO(indutny): support other responders
  var signAlg = ocsp.utils.sign[res.signatureAlgorithm.algorithm.join('.')];
  if (!signAlg) {
    done(new Error('Unknown signature algorithm ' +
        res.signatureAlgorithm.algorithm));
    return;
  }

  var verify = crypto.createVerify(signAlg);
  var tbs = res.tbsResponseData;

  var issuerKey = issuer.tbsCertificate.subjectPublicKeyInfo;
  issuerKey = ocsp.utils.toPEM(
      rfc3280.SubjectPublicKeyInfo.encode(issuerKey, 'der'), 'PUBLIC KEY');
  var signature = res.signature.data;

  // if the ocsp response contains a certificate, we need to do additional
  // verification
  if (res && res.certs && res.certs[0]) {
    var cert = res.certs[0];
    if (cert.tbsCertificate && cert.tbsCertificate.subjectPublicKeyInfo) {
      // verify that the certificate signature matches the issuer key
      var certVerify = crypto.createVerify(
          ocsp.utils.sign[cert.signatureAlgorithm.algorithm.join('.')]);
      certVerify.update(rfc3280.TBSCertificate.encode(cert.tbsCertificate, 'der'));

      if (!certVerify.verify(issuerKey, cert.signature.data))
        return done(new Error('Invalid signature'));

      // get the public key from the certificate; we'll use it to verify the
      // signature of the ocsp response
      issuerKey = ocsp.utils.toPEM(
          rfc3280.SubjectPublicKeyInfo.encode(
              cert.tbsCertificate.subjectPublicKeyInfo, 'der'), 'PUBLIC KEY');
    }
  }

  verify.update(rfc2560.ResponseData.encode(tbs, 'der'));
  if (!verify.verify(issuerKey, signature))
    return done(new Error('Invalid signature'));

  if (tbs.responses.length < 1)
    return done(new Error('Expected at least one response'));

  res = tbs.responses[0];

  // Verify CertID
  // XXX(indutny): verify parameters
  if (res.certId.hashAlgorithm.algorithm.join('.') !==
      req.certID.hashAlgorithm.algorithm.join('.')) {
    return done(new Error('Hash algorithm mismatch'));
  }

  if (res.certId.issuerNameHash.toString('hex') !==
      req.certID.issuerNameHash.toString('hex')) {
    return done(new Error('Issuer name hash mismatch'));
  }

  if (res.certId.issuerKeyHash.toString('hex') !==
      req.certID.issuerKeyHash.toString('hex')) {
    return done(new Error('Issuer key hash mismatch'));
  }

  if (res.certId.serialNumber.cmp(req.certID.serialNumber) !== 0)
    return done(new Error('Serial number mismatch'));

  if (res.certStatus.type !== 'good') {
    return done(new Error('OCSP Status: ' + res.certStatus.type));
  }

  var now = +new Date();
  var nudge = options.nudge || 60000;
  if (res.thisUpdate - nudge > now || res.nextUpdate + nudge < now)
    return done(new Error('OCSP Response expired'));

  return done(null);
};