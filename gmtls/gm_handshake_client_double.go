// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !single_cert

package gmtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"io"
	"sync/atomic"
)

type clientHandshakeStateGM struct {
	c            *Conn
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

func (c *Conn) makeClientHelloGM() (*clientHelloMsg, ecdheParameters, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("tls: NextProtos values too large")
	}
	possibleCipherSuites := getCipherSuites(config)

	hello := &clientHelloMsg{
		vers:                         VersionGMSSL,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		supportedVersions:			  []uint16{VersionGMSSL},
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}


	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

	for _, suiteId := range possibleCipherSuites {
		for _, suite := range config.GMSupport.cipherSuites() {
			if suite.id != suiteId {
				continue
			}
			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				break
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			break
		}
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}

	var params ecdheParameters
	if hello.supportedVersions[0] == VersionTLS13 {
		hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13()...)

		curveID := config.curvePreferences()[0]
		if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
			return nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		}
		params, err = generateECDHEParameters(config.rand(), curveID)
		if err != nil {
			return nil, nil, err
		}
		hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	return hello, params, nil
}

// Does the handshake, either a full one or resumes old session.
// Requires hs.c, hs.hello, and, optionally, hs.session to be set.
func (hs *clientHandshakeStateGM) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHashGM(hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.didResume = isResume
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeStateGM) pickCipherSuite() error {
	if hs.suite = mutualCipherSuiteGM(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeStateGM) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	// mod by syl only one cert
	// Thanks to dual certificates mechanism, length of certificates in GMT0024 must great than 2
	if len(certMsg.certificates) < 2 {
		c.sendAlert(alertInsufficientSecurity)
		return fmt.Errorf("tls: length of certificates in GMT0024 must great than 2")
	}

	hs.finishedHash.Write(certMsg.marshal())

	if c.handshakes == 0 {
		certs := make([]*x509.Certificate, len(certMsg.certificates))
		for i, asn1Data := range certMsg.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}

			pubKey, _ := cert.PublicKey.(*ecdsa.PublicKey)
			if pubKey.Curve != sm2.P256Sm2() {
				c.sendAlert(alertUnsupportedCertificate)
				return fmt.Errorf("tls: pubkey type of cert is error, expect sm2.publicKey")
			}

			//cert[0] is for signature while cert[1] is for encipher, refer to  GMT0024
			//check key usage
			switch i {
			case 0:
				if cert.KeyUsage == 0 || (cert.KeyUsage&(x509.KeyUsageDigitalSignature|cert.KeyUsage&x509.KeyUsageContentCommitment)) == 0 {
					c.sendAlert(alertInsufficientSecurity)
					return fmt.Errorf("tls: the keyusage of cert[0] does not exist or is not for KeyUsageDigitalSignature/KeyUsageContentCommitment, value:%d", cert.KeyUsage)
				}
			case 1:
				if cert.KeyUsage == 0 || (cert.KeyUsage&(x509.KeyUsageDataEncipherment|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement)) == 0 {
					c.sendAlert(alertInsufficientSecurity)
					return fmt.Errorf("tls: the keyusage of cert[1] does not exist or is not for KeyUsageDataEncipherment/KeyUsageKeyEncipherment/KeyUsageKeyAgreement, value:%d", cert.KeyUsage)
				}
			}

			certs[i] = cert
		}

		if !c.config.InsecureSkipVerify {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			if opts.Roots == nil {
				opts.Roots = x509.NewCertPool()
			}

			for _, rootca := range getCAs() {
				opts.Roots.AddCert(rootca)
			}
			for i, cert := range certs {
				c.verifiedChains, err = certs[i].Verify(opts)
				if err != nil {
					c.sendAlert(alertBadCertificate)
					return err
				}
				if i == 0 || i == 1 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

		}

		if c.config.VerifyPeerCertificate != nil {
			if err := c.config.VerifyPeerCertificate(certMsg.certificates, c.verifiedChains); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}

		switch certs[0].PublicKey.(type) {
		case *sm2.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey:
			break
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
		}

		c.peerCertificates = certs
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	// 以下分支是新版本中的内容，尝试看看能否使用
	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}
		hs.finishedHash.Write(cs.marshal())

		c.ocspResponse = cs.response

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	keyAgreement := hs.suite.ka(c.vers)
	if ka, ok := keyAgreement.(*eccKeyAgreementGM); ok {
		ka.encipherCert = c.peerCertificates[1]
	}

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsgGM)
	if ok {
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		cri := certificateRequestGMInfoFromMsg(certReq)

		cri.SignatureSchemes = append(cri.SignatureSchemes, SM2WITHSM3)

		if chainToSend, err = c.getClientCertificateGM(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[1])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= VersionTLS12,
		}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		// 以下内容其实与handshake_client.go差不多，只是更加明确是用国密的算法来实现
		signatureAlgorithm, _, _, err := pickSignatureAlgorithm(key.Public(), certReq.supportedSignatureAlgorithms, supportedSignatureAlgorithmsTLS12, c.vers)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		// SignatureAndHashAlgorithm was introduced in TLS 1.2.
		if certVerify.hasSignatureAlgorithm {
			certVerify.signatureAlgorithm = signatureAlgorithm
		}

		digest := hs.finishedHash.client.Sum(nil)

		certVerify.signature, err = key.Sign(c.config.rand(), digest, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeStateGM) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeStateGM) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeStateGM) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}
	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret and peerCerts from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return true, nil
}

func (hs *clientHandshakeStateGM) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeStateGM) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
	}

	return nil
}

func (hs *clientHandshakeStateGM) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, nextProto.marshal()); err != nil {
			return err
		}
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

//// tls11SignatureSchemes contains the signature schemes that we synthesise for
//// a TLS <= 1.1 connection, based on the supported certificate types.
//var tls11SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1}
//
//const (
//	// tls11SignatureSchemesNumECDSA is the number of initial elements of
//	// tls11SignatureSchemes that use ECDSA.
//	tls11SignatureSchemesNumECDSA = 3
//	// tls11SignatureSchemesNumRSA is the number of trailing elements of
//	// tls11SignatureSchemes that use RSA.
//	tls11SignatureSchemesNumRSA = 4
//)

// certificateRequestInfoFromMsg generates a CertificateRequestInfo from a TLS
// <= 1.2 CertificateRequest, making an effort to fill in missing information.
func certificateRequestGMInfoFromMsg(certReq *certificateRequestMsgGM) *CertificateRequestInfo {
	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
	}

	if !certReq.hasSignatureAlgorithm {
		// Prior to TLS 1.2, the signature schemes were not
		// included in the certificate request message. In this
		// case we use a plausible list based on the acceptable
		// certificate types.
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = tls11SignatureSchemes
		case rsaAvail:
			cri.SignatureSchemes = tls11SignatureSchemesRSA
		case ecAvail:
			cri.SignatureSchemes = tls11SignatureSchemesECDSA
		}
		return cri
	}

	// Filter the signature schemes based on the certificate types.
	// See RFC 5246, Section 7.4.4 (where it calls this "somewhat complicated").
	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		switch signatureFromSignatureScheme(sigScheme) {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}