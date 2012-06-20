package edu.umass.cs.gcrs.server;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.SHA1HashFunction;
import edu.umass.cs.gcrs.utilities.Utils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.prefs.Preferences;
import org.json.simple.JSONObject;

/**
 * Implements an example client for the line parsing based server
 * 
 * @author westy
 */
class NotTheHTTPClient {

  Socket serverSocket = null;
  PrintWriter outToServer = null;
  BufferedReader inFromServer = null;
  private static Preferences userPrefs;
  
  private static String HOST = "ec2-107-22-72-223.compute-1.amazonaws.com";
  // private static String HOST = "127.0.0.1";

  public static Preferences getUserPreferences() {
    return userPrefs;
  }

  public static void main(String argv[]) throws Exception {
    userPrefs = Preferences.userRoot().node(NotTheHTTPClient.class.getName());
    new NotTheHTTPClient().run();
  }

  // IF YOU RUN THIS A SECOND TIME WITHOUT DELETING SOME OF THE USER INFO YOU'LL GET ERRORS... JUST SO YOU KNOW!!!
  public void run() {

    try {
      serverSocket = new Socket(HOST, GCRS.SERVERPORT);
      outToServer = new PrintWriter(serverSocket.getOutputStream(), true);
      inFromServer = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));

      //registerNewUser("westy");
      //registerNewUser("sam");

      //String westyGuid = lookupUserGuid("westy");
      //String samGuid = lookupUserGuid("sam");
      
      String westyGuid = registerNewUserReturnGuid("westy");
      String samGuid = registerNewUserReturnGuid("sam");

      System.out.println("Result of registerNewUserReturnGuid for westy is: " + westyGuid);
      System.out.println("Result of registerNewUserReturnGuid for sam is: " + samGuid);

      writeField(westyGuid, "location", "work");
      
      JSONObject jsonObject = new JSONObject();
      jsonObject.put("ssn", "000-00-0000");
      jsonObject.put("password", "666flapJack");
      jsonObject.put("petname", "slinker");
      jsonObject.put("address", "100 Hinkledinkle Drive");
      
      writeFields(westyGuid, jsonObject.toString());

      // read my own field
      String result = readField(westyGuid, "location", westyGuid);

      System.out.println("Result of read of westy location by westy is: " + result);
      
      // read another field
      result = readField(westyGuid, "ssn", westyGuid);
      System.out.println("Result of read of westy ssn by westy is: " + result);
      
      // read another field
      result = readField(westyGuid, "address", westyGuid);
      System.out.println("Result of read of westy address by westy is: " + result);

      addToACL(westyGuid, "location", samGuid);

      result = readField(westyGuid, "location", samGuid);

      System.out.println("Result of read of westy location by sam is: " + result);

      registerNewUser("barney");
      String barneyGuid = lookupUserGuid("barney");

      writeField(barneyGuid, "cell", "413-555-1234");
      writeField(barneyGuid, "address", "100 Main Street");

      // let anybody read barney's cell field
      addToACL(barneyGuid, "cell", Protocol.ALLUSERS);

      result = readField(barneyGuid, "cell", samGuid);
      System.out.println("Result of read of barney's cell by sam is: " + result);

      result = readField(barneyGuid, "cell", westyGuid);
      System.out.println("Result of read of barney's cell by westy is: " + result);

      registerNewUser("superuser");
      String superuserGuid = lookupUserGuid("superuser");

      // let superuser read any of barney's fields
      addToACL(barneyGuid, Protocol.ALLFIELDS, superuserGuid);

      result = readField(barneyGuid, "cell", superuserGuid);
      System.out.println("Result of read of barney's cell by superuserGuid is: " + result);

      result = readField(barneyGuid, "address", superuserGuid);
      System.out.println("Result of read of barney's address by superuserGuid is: " + result);

      outToServer.close();
      inFromServer.close();

    } catch (IOException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (NoSuchAlgorithmException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (InvalidKeyException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (SignatureException e) {
      GCRS.getLogger().severe(e.toString());
    } finally {
      if (serverSocket != null) {
        try {
          serverSocket.close();
        } catch (IOException e) {
          GCRS.getLogger().severe(e.toString());
        }
      }
    }
  }

  private void registerNewUser(String username) throws IOException, NoSuchAlgorithmException {

    KeyPair keyPair = KeyPairGenerator.getInstance(Protocol.RASALGORITHM).generateKeyPair();
    saveKeyPairToPreferences(username, keyPair);

    PublicKey publicKey = keyPair.getPublic();
    byte[] publicKeyBytes = publicKey.getEncoded();
    String publicKeyString = Utils.toHex(publicKeyBytes);

    byte[] publicKeyDigest = SHA1HashFunction.getInstance().hash(publicKeyBytes);
    String guid = Utils.toHex(publicKeyDigest);

    saveKeyPairToPreferences(guid, keyPair);

    String message = Protocol.REGISTERENTITY + " " + username + " " + guid + " " + publicKeyString;
    //String message = "register " + publicKeyDigestString + " " + "fred";
    String response;

    outToServer.println(message);
    System.out.println("Sent " + message);

    response = inFromServer.readLine();
    System.out.println("Value returned: " + response);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      System.out.println("Problem registering user");
      return;
    }
  }

  private String registerNewUserReturnGuid(String username) throws IOException, NoSuchAlgorithmException {

    KeyPair keyPair = KeyPairGenerator.getInstance(Protocol.RASALGORITHM).generateKeyPair();
    saveKeyPairToPreferences(username, keyPair);

    PublicKey publicKey = keyPair.getPublic();
    byte[] publicKeyBytes = publicKey.getEncoded();
    String publicKeyString = Utils.toHex(publicKeyBytes);

    String message = Protocol.REGISTERENTITY + " " + username + " " + publicKeyString;

    outToServer.println(message);
    System.out.println("Sent " + message);

    String response = inFromServer.readLine();
    System.out.println("Value returned: " + response);

    String[] tokens = response.split(" ");
    String guid = tokens[0];

    saveKeyPairToPreferences(guid, keyPair);

    if (response.startsWith(Protocol.BADRESPONSE)) {
      System.out.println("Problem registering user");
      return null;
    } else {
      return guid;
    }
  }

  private String lookupUserGuid(String username) throws IOException {
    String message = Protocol.LOOKUPENTITY + " " + username;
    outToServer.println(message);
    String[] tokens = inFromServer.readLine().split(" ");
    String guid = tokens[0];
    System.out.println("guid = " + guid);
    return guid;
  }

  /**  insertOne <guid> <field> <value> <signature> **/
  private void writeField(String guid, String field, String value) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

    String message = signMessage(guid, Protocol.INSERTONE + " " + guid + " " + field + " " + value);
    outToServer.println(message);
    //System.out.println("Sent " + message);

    String response = inFromServer.readLine();
    //System.out.println("Read " + response);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      System.out.println("Problem sending write");
    }

  }
  
  /**  insertOne <guid> <josn> <signature> **/
  private void writeFields(String guid, String json) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

    String message = signMessage(guid, Protocol.INSERT + " " + guid + " " + json);
    outToServer.println(message);
    //System.out.println("Sent " + message);

    String response = inFromServer.readLine();
    //System.out.println("Read " + response);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      System.out.println("Problem sending write");
    }

  }

  /** read <username> <field> <readerusername> <signature> **/
  private String readField(String guid, String field, String reader) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

    String message = signMessage(reader, Protocol.LOOKUP + " " + guid + " " + field + " " + reader);
    outToServer.println(message);
    //System.out.println("Sent " + message);

    String response = inFromServer.readLine();

    if (!response.startsWith(Protocol.BADRESPONSE)) {
      System.out.println("Value returned: " + response);
      return response;
    } else {
      return null;
    }
  }

  /** read <username> <field> <readerusername> <signature> **/
  private void addToACL(String guid, String field, String reader) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    String message = signMessage(guid, Protocol.ACLADD + " " + guid + " " + field + " " + reader);
    outToServer.println(message);
    System.out.println("Sent " + message);

    String response = inFromServer.readLine();
    //System.out.println("Read " + response);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      System.out.println("Problem sending write");
    }
  }

  private String signMessage(String guid, String message) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    byte[] messageDigest = SHA1HashFunction.getInstance().hash(message.getBytes());

    KeyPair keyPair = getKeyPairFromPreferences(guid);
    //KeyPair keyPair = guidToKeyPair.get(guid);
    PrivateKey privateKey = keyPair.getPrivate();
    Signature instance = Signature.getInstance(Protocol.SIGNATUREALGORITHM);

    instance.initSign(privateKey);
    instance.update(messageDigest);
    byte[] signature = instance.sign();
    String signatureString = Utils.toHex(signature);

    return message + " " + signatureString;
  }

  private void saveKeyPairToPreferences(String username, KeyPair keyPair) {
    String publicString = Utils.toHex(keyPair.getPublic().getEncoded());
    String privateString = Utils.toHex(keyPair.getPrivate().getEncoded());
    getUserPreferences().put(username + "-public", publicString);
    getUserPreferences().put(username + "-private", privateString);
  }

  private KeyPair getKeyPairFromPreferences(String username) {
    String publicString = getUserPreferences().get(username + "-public", "");
    String privateString = getUserPreferences().get(username + "-private", "");
    if (!publicString.isEmpty() && !privateString.isEmpty()) {
      try {
        byte[] encodedPublicKey = Utils.hexStringToByteArray(publicString);
        byte[] encodedPrivateKey = Utils.hexStringToByteArray(privateString);

        KeyFactory keyFactory = KeyFactory.getInstance(Protocol.RASALGORITHM);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
      } catch (NoSuchAlgorithmException e) {
        GCRS.getLogger().severe(e.toString());
        return null;
      } catch (InvalidKeySpecException e) {
        GCRS.getLogger().severe(e.toString());
        return null;
      }

    } else {
      return null;
    }
  }
}
