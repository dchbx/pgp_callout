package gov.dc.dchbx.pgp.callout;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import oracle.tip.b2b.callout.Callout;
import oracle.tip.b2b.callout.CalloutContext;
import oracle.tip.b2b.callout.CalloutMessage;
import oracle.tip.b2b.callout.exception.CalloutDomainException;
import oracle.tip.b2b.callout.exception.CalloutSystemException;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

/**
 *
 * @author tevans
 */
public class PgpEncryptor implements Callout {
  
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
      logMessage(isDebugging, "<<<<<BEGINNING CALLOUT FOR PGPENCRYPTOR>>>>>");
      logMessage(isDebugging, "<<<<<CALLOUT PROPERTIES:>>>>>");
      Map ccProps = cc.getCalloutProperties();
      for (Object item : ccProps.entrySet()) {
        Map.Entry kv = Map.Entry.class.cast(item);
        logMessage(isDebugging, kv.getKey().toString() + " : " + kv.getValue().toString() + "\n");
      }
      logMessage(isDebugging, "<<<<<GETTING MESSAGE>>>>>");
      msg = (CalloutMessage) in.get(0);
      logMessage(isDebugging, "<<<<<MESSAGE PROPERTIES:>>>>>");
      Properties msgProps = msg.getParameters();
      for (Map.Entry mpkv : msgProps.entrySet()) {
        logMessage(isDebugging, mpkv.getKey().toString() + " : " + mpkv.getValue().toString() + "\n");
      }
      logMessage(isDebugging, "<<<<<GETTING FILENAME>>>>>");
      String targetFileName = msgProps.getProperty("filename");
      if (targetFileName.lastIndexOf(".pgp") > 0) {
        targetFileName = targetFileName.substring(0, targetFileName.lastIndexOf(".pgp"));
      }
      logMessage(isDebugging, "<<<<<GETTING KEYPATH>>>>>");
      String keyPath = cc.getStringProperty("KeyPath");
      logMessage(isDebugging, "<<<<<KEYPATH: " + keyPath + " >>>>>");
      logMessage(isDebugging, "<<<<<GETTING KEY FILE>>>>>");
      InputStream fip = new FileInputStream(keyPath);
      logMessage(isDebugging, "<<<<<GETTING PUBLIC KEY>>>>>");
      PGPPublicKey key = GetPublicKey(fip);
      ByteArrayOutputStream outStream = new ByteArrayOutputStream();
      logMessage(isDebugging, "<<<<<ENCRYPTING USING PUBLIC KEY>>>>>");
      EncryptStream(targetFileName, key, msg.getBodyAsInputStream(), outStream);
      fip.close();
      logMessage(isDebugging, "<<<<<ADDING CALLOUT RESULT>>>>>");
      CalloutMessage result = new CalloutMessage();
      result.setBody(outStream.toByteArray());
      out.add(result);
      logMessage(isDebugging, "<<<<<FINISHED CALLOUT FOR PGPENCRYPTOR>>>>>");
    } catch (Exception e) {
      // We have failed xCore - log the error, and pass the original payload
      // through to prevent issues
      System.err.println("<<<<<PGPENCRYPTOR CALLOUT FAILED, STACKTRACE FOLLOWS>>>>>");
      System.err.println(e.getMessage());
      System.err.println(e.toString());
      e.printStackTrace(System.err);
      throw new CalloutSystemException(e);
    }
  }

  public PGPPublicKey GetPublicKey(InputStream keyBlock) throws IOException, PGPException {
    PGPPublicKeyRingCollection pgpSec = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyBlock));
    Iterator<PGPPublicKeyRing> iter = pgpSec.getKeyRings();
    List<PGPPublicKey> secKeys = new ArrayList<PGPPublicKey>();
    PGPPublicKey currentKey = null;
    while (iter.hasNext()) {
      PGPPublicKeyRing keyRing = iter.next();
      Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
      while (keyIter.hasNext()) {
        currentKey = keyIter.next();
        if (currentKey.isEncryptionKey()) {
          secKeys.add(currentKey);
          break;
        }
      }
    }
    return secKeys.get(secKeys.size() - 1);
  }

  public void EncryptStream(String outName, PGPPublicKey key, InputStream data, OutputStream out) throws IOException, PGPException {
    OutputStream outStream = new ArmoredOutputStream(out);
    BcPGPDataEncryptorBuilder deb = new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256);
    deb.setSecureRandom(new SecureRandom());
    deb.setWithIntegrityPacket(true);
    BcPublicKeyKeyEncryptionMethodGenerator encMethod = new BcPublicKeyKeyEncryptionMethodGenerator(key);
    PGPEncryptedDataGenerator gen = new PGPEncryptedDataGenerator(deb);
    gen.addMethod(encMethod);
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
    byte[] buffer = new byte[128];
    OutputStream lOut = lData.open(bOut, PGPLiteralData.BINARY, outName, PGPLiteralData.NOW, buffer);
    int ch;
    while ((ch = data.read()) >= 0) {
      lOut.write(ch);
    }
    lOut.close();
    OutputStream writerStream = gen.open(outStream, buffer);
    writerStream.write(bOut.toByteArray());
    bOut.close();
    writerStream.close();
    outStream.close();
    out.close();
  }
}
