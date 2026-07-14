/*
 * Copyright 2011 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.crypto;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.PrivateKey;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Implementation <code>KeyAgreement</code> based
 * on BouncyCastle CryptoAPI.
 * @see KeyAgreement
 * @see ECDHBasicAgreement
 * @see ECDHCBasicAgreement
 */
public class KeyAgreementImpl extends KeyAgreement {

    BasicAgreement engine;
    SHA1Digest digestEngine;
    
    byte algorithm;
    ECPrivateKeyImpl privateKey;

    public KeyAgreementImpl(byte algorithm) {
        this.algorithm = algorithm;
        switch (algorithm) {
            case ALG_EC_SVDP_DH: // no break
            case ALG_EC_SVDP_DH_PLAIN:
                engine = new ECDHBasicAgreement();
                break;
            case ALG_EC_SVDP_DH_PLAIN_XY:
                engine = new ECDHBasicAgreementXY();
                break;
            case ALG_EC_SVDP_DHC: // no break
            case ALG_EC_SVDP_DHC_PLAIN:
                engine = new ECDHCBasicAgreement();
                break;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
        digestEngine = new SHA1Digest();
    }

    public void init(PrivateKey privateKey) throws CryptoException {
        if (privateKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(privateKey instanceof ECPrivateKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        engine.init(((ECPrivateKeyImpl) privateKey).getParameters());
        this.privateKey = (ECPrivateKeyImpl) privateKey;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    /**
     * Rejects public points that are not on the private key's curve, like real cards do.
     * BouncyCastle 1.46 does not validate decoded points itself, which makes the outcome
     * of an agreement with an invalid point (e.g. 0,0) depend on the private scalar.
     */
    private static void checkOnCurve(org.bouncycastle.math.ec.ECPoint point) throws CryptoException {
        if (point.isInfinity()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (point instanceof org.bouncycastle.math.ec.ECPoint.Fp) {
            org.bouncycastle.math.ec.ECFieldElement x = point.getX();
            org.bouncycastle.math.ec.ECFieldElement y = point.getY();
            org.bouncycastle.math.ec.ECFieldElement lhs = y.square();
            org.bouncycastle.math.ec.ECFieldElement rhs = x.square().multiply(x)
                    .add(point.getCurve().getA().multiply(x))
                    .add(point.getCurve().getB());
            if (!lhs.equals(rhs)) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
        }
    }

    public short generateSecret(byte[] publicData,
            short publicOffset,
            short publicLength,
            byte[] secret,
            short secretOffset) throws CryptoException {
        byte[] publicKey = new byte[publicLength];
        Util.arrayCopyNonAtomic(publicData, publicOffset, publicKey, (short) 0, publicLength);
        byte[] num;
        try {
            org.bouncycastle.math.ec.ECPoint point =
                    ((ECPrivateKeyParameters) privateKey.getParameters()).getParameters().getCurve().decodePoint(publicKey);
            checkOnCurve(point);
            ECPublicKeyParameters ecp = new ECPublicKeyParameters(
                    point, ((ECPrivateKeyParameters) privateKey.getParameters()).getParameters());
            num = engine.calculateAgreement(ecp).toByteArray();
        } catch (CryptoException e) {
            throw e;
        } catch (RuntimeException e) {
            // real cards reject invalid public points with ILLEGAL_VALUE instead of
            // leaking the underlying provider exception
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            return (short) -1;
        }
        byte[] result;

        if (this.algorithm != ALG_EC_SVDP_DH_PLAIN_XY) {
            // truncate/zero-pad to field size as per the spec:
            int fieldSize = privateKey.getDomainParameters().getCurve().getFieldSize();
            result = new byte[(fieldSize + 7) / 8];
            int numBytes = Math.min(num.length, result.length);
            Util.arrayCopyNonAtomic(
                num, (short) (num.length - numBytes),
                result, (short) (result.length - numBytes),
                (short) numBytes);
            Util.arrayFillNonAtomic(result, (short) 0, (short) (result.length - numBytes), (byte) 0);
        } else {
            result = num;
        }

        // post-process output key based on agreement type
        switch (this.algorithm) {
            case ALG_EC_SVDP_DH: // no break
            case ALG_EC_SVDP_DHC: 
                // apply SHA1-hash (see spec)
                byte[] hashResult = new byte[20];
                digestEngine.update(result, 0, result.length);
                digestEngine.doFinal(hashResult, 0);
                Util.arrayCopyNonAtomic(hashResult, (short) 0, secret, secretOffset, (short) hashResult.length);
                return (short) hashResult.length;
            case ALG_EC_SVDP_DHC_PLAIN: // no break
            case ALG_EC_SVDP_DH_PLAIN:
            case ALG_EC_SVDP_DH_PLAIN_XY:
                // plain output
                Util.arrayCopyNonAtomic(result, (short) 0, secret, secretOffset, (short) result.length);
                return (short) result.length;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
        return (short) -1;
    }
}
