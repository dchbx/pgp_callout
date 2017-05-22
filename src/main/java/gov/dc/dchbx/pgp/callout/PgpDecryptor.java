package gov.dc.dchbx.pgp.callout;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import oracle.tip.b2b.callout.Callout;
import oracle.tip.b2b.callout.CalloutContext;
import oracle.tip.b2b.callout.CalloutMessage;
import oracle.tip.b2b.callout.exception.CalloutDomainException;
import oracle.tip.b2b.callout.exception.CalloutSystemException;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

/**
 *
 * @author tevans
 */
public class PgpDecryptor implements Callout {
  
  private void logMessage(Boolean isDebug, String message) {
    if (isDebug)
    {
      System.err.println(message);
    }
  }

  public void execute(CalloutContext cc, List in, List out) throws CalloutDomainException, CalloutSystemException {
    CalloutMessage msg;
    try {
      Boolean isDebugging = false;
      if (cc.isCalloutProperty("Debug")) {
        isDebugging = cc.getStringProperty("Debug").equals("TRUE");
      }
      logMessage(isDebugging, "<<<<<BEGINNING CALLOUT FOR PGPDECRYPTOR>>>>>");
      logMessage(isDebugging, "<<<<<CALLOUT PROPERTIES:>>>>>");
      Map ccProps = cc.getCalloutProperties();
      for (Object item : ccProps.entrySet()) {
        Entry kv = Entry.class.cast(item);
        logMessage(isDebugging, kv.getKey().toString() + " : " + kv.getValue().toString() + "\n");
      }
      logMessage(isDebugging, "<<<<<GETTING MESSAGE>>>>>");
      msg = (CalloutMessage) in.get(0);
      logMessage(isDebugging, "<<<<<MESSAGE PROPERTIES:>>>>>");
      Properties msgProps = msg.getParameters();
      for (Entry mpkv : msgProps.entrySet()) {
        logMessage(isDebugging, mpkv.getKey().toString() + " : " + mpkv.getValue().toString() + "\n");
      }
      logMessage(isDebugging, "<<<<<GETTING KEY PASSWORD>>>>>");
      String keyPass = cc.getStringProperty("PrivateKeyPassword");
      logMessage(isDebugging, "<<<<<GETTING KEYPATH>>>>>");
      String keyPath = cc.getStringProperty("KeyPath");
      logMessage(isDebugging, "<<<<<KEYPATH: " + keyPath + " >>>>>");
      logMessage(isDebugging, "<<<<<GETTING KEY FILE>>>>>");
      InputStream fip = new FileInputStream(keyPath);
      logMessage(isDebugging, "<<<<<GETTING SECRET KEY>>>>>");
      List<PGPSecretKey> key = GetPrivateKey(fip);
      ByteArrayOutputStream outStream = new ByteArrayOutputStream();
      logMessage(isDebugging, "<<<<<DECRYPTING USING SECRET KEY>>>>>");
      DecryptStream(key, keyPass, msg.getBodyAsInputStream(), outStream);
      fip.close();
      logMessage(isDebugging, "<<<<<ADDING CALLOUT RESULT>>>>>");
      CalloutMessage result = new CalloutMessage(outStream.toByteArray());
      out.add(result);
      logMessage(isDebugging, "<<<<<FINISHED CALLOUT FOR PGPDECRYPTOR>>>>>");
    } catch (Exception e) {
      // We have failed xCore - log the error, and pass the original payload
      // through to prevent issues
      System.err.println("<<<<<PGPDECRYPTOR CALLOUT FAILED, STACKTRACE FOLLOWS>>>>>");
      System.err.println(e.getMessage());
      System.err.println(e.toString());
      e.printStackTrace(System.err);
      msg = (CalloutMessage)in.get(0);
      CalloutMessage result = new CalloutMessage(msg.getBodyAsBytes());
      out.add(result);
    }
  }

  public List<PGPSecretKey> GetPrivateKey(InputStream keyBlock) throws IOException, PGPException {
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyBlock));
    Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
    PGPSecretKey currentKey;
    List<PGPSecretKey> keyList = new ArrayList<PGPSecretKey>();
    while (iter.hasNext()) {
      PGPSecretKeyRing keyRing = iter.next();
      Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
      while (keyIter.hasNext()) {
        currentKey = keyIter.next();
        if (!currentKey.isPrivateKeyEmpty()){
          keyList.add(currentKey);
        }
      }
    }
    return keyList;
  }

  public void DecryptStream(List<PGPSecretKey> key, String pass, InputStream data, OutputStream out) throws IOException, PGPException {
    PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass.toCharArray());
    
    //PGPPrivateKey pKey = key.extractPrivateKey(decryptor);

    PGPObjectFactory pgpF = new PGPObjectFactory(PGPUtil.getDecoderStream(data));
    PGPEncryptedDataList enc;

    Object o = pgpF.nextObject();
    //
    // the first object might be a PGP marker packet.
    //
    if (o instanceof PGPEncryptedDataList) {
      enc = (PGPEncryptedDataList) o;
    } else {
      enc = (PGPEncryptedDataList) pgpF.nextObject();
    }
    Iterator<PGPPublicKeyEncryptedData> items = enc.getEncryptedDataObjects();
    PGPPublicKeyEncryptedData pbe = items.next();
    
    long keyId = pbe.getKeyID();
    PGPSecretKey sKey = null;
    
    for (PGPSecretKey k : key) {
      if (k.getKeyID() == keyId) {
        sKey = k;
        break;
      }
    }
    
    PGPPrivateKey pKey = sKey.extractPrivateKey(decryptor);
    
    InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(pKey));

    PGPObjectFactory plainFact = new PGPObjectFactory(clear);
    Object message = plainFact.nextObject();

    if (message instanceof PGPCompressedData) {
      PGPCompressedData cData = (PGPCompressedData) message;
      PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
      message = pgpFact.nextObject();
    }
    if (message instanceof PGPLiteralData) {
      PGPLiteralData ld = (PGPLiteralData) message;
      InputStream unc = ld.getInputStream();
      int ch;

      while ((ch = unc.read()) >= 0) {
        out.write(ch);
      }
    } else if (message instanceof PGPOnePassSignatureList) {
      throw new PGPException("Encrypted message contains a signed message - not literal data.");
    } else {
      throw new PGPException("Message is not a simple encrypted file - type unknown.");
    }


  }
}
