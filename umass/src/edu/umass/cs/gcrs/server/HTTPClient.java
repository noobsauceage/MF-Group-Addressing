package edu.umass.cs.gcrs.server;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.SHA1HashFunction;
import edu.umass.cs.gcrs.utilities.URIEncoderDecoder;
import edu.umass.cs.gcrs.utilities.Utils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
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
import static edu.umass.cs.gcrs.server.Defs.*;

/**
 * Implements an example client for the GCRS HTTP server
 * 
 * @author westy
 */
public class HTTPClient {

  /**
   * The address of the GCRS server we will contact
   */
  public static String HOST = "http://umassmobilityfirst.net";
  //private static String HOST = "http://127.0.0.1:8080";
  //
  /** 
   * Save the public/private key using Preferences 
   */
  private static Preferences userPreferencess;

  /**
   * Main which runs the runClientTest method.
   * 
   */
  public static void main(String argv[]) throws Exception {
    userPreferencess = Preferences.userRoot().node(HTTPClient.class.getName());
    new HTTPClient().runClientTest();
  }

  /** 
   * Send a bunch of test queries to the server 
   */
  public void runClientTest() {

    try {

      sendGetCommand("demo?passkey=umass"); // turn on demo mode
      // When running this as a test we need to clear the database otherwise the users will already exist
      sendGetCommand("clear"); // clear the database
      sendGetCommand("demo?passkey=off"); // turn off demo mode

      String westyGuid = registerNewUser("westy");
      String samGuid = registerNewUser("sam");

      System.out.println("Result of registerNewUser for westy is: " + westyGuid);
      System.out.println("Result of registerNewUser for sam is: " + samGuid);

      writeField(westyGuid, "location", "work");

      // create a json object so pass the string representation to writeFields
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

      try {
        result = readField(westyGuid, "location", samGuid);
        System.out.println("Result of read of westy location by sam is " + result);
      } catch (RuntimeException e) {
        System.out.println("Result of read of westy location by sam was incorrectly rejected.");
      }

      String barneyGuid = registerNewUser("barney");

      writeField(barneyGuid, "cell", "413-555-1234");
      writeField(barneyGuid, "address", "100 Main Street");

      // let anybody read barney's cell field
      addToACL(barneyGuid, "cell", Protocol.ALLUSERS);

      try {
        result = readField(barneyGuid, "cell", samGuid);
        System.out.println("Result of read of barney's cell by sam is " + result);
      } catch (RuntimeException e) {
        System.out.println("Result of read of barney's cell by sam was incorrectly rejected.");
      }

      try {
        result = readField(barneyGuid, "address", samGuid);
        System.out.println("Result of read of barney's address by sam is " + result);
      } catch (RuntimeException e) {
        System.out.println("Result of read of barney's address by sam was correctly rejected.");
      }


      try {
        result = readField(barneyGuid, "cell", westyGuid);
        System.out.println("Result of read of barney's cell by westy is " + result);
      } catch (RuntimeException e) {
        System.out.println("Result of read of barney's cell by westy was incorrectly rejected.");
      }

      String superuserGuid = registerNewUser("superuser");
      System.out.println("Result of registerNewUser for superuser is: " + superuserGuid);


      // let superuser read any of barney's fields
      addToACL(barneyGuid, Protocol.ALLFIELDS, superuserGuid);

      result = readField(barneyGuid, "cell", superuserGuid);
      System.out.println("Result of read of barney's cell by superuserGuid is: " + result);

      result = readField(barneyGuid, "address", superuserGuid);
      System.out.println("Result of read of barney's address by superuserGuid is: " + result);

      // TEST GROUPS

      String command = createQuery(Protocol.CREATEGROUP, Protocol.NAME, "mygroup", Protocol.PUBLICKEY, "dummykey");
      String response = sendGetCommand(command);

      command = createQuery(Protocol.LOOKUPGROUP, Protocol.NAME, "mygroup");
      String groupGuid = sendGetCommand(command);

      command = createQuery(Protocol.ADDTOGROUP, Protocol.GROUP, groupGuid, Protocol.GUID, westyGuid);
      response = sendGetCommand(command);

      command = createQuery(Protocol.ADDTOGROUP, Protocol.GROUP, groupGuid, Protocol.GUID, samGuid);
      response = sendGetCommand(command);

      command = createQuery(Protocol.ADDTOGROUP, Protocol.GROUP, groupGuid, Protocol.GUID, barneyGuid);
      response = sendGetCommand(command);

      command = createQuery(Protocol.GETGROUPMEMBERS, Protocol.GROUP, groupGuid);
      String groupMembers = sendGetCommand(command);

      System.out.println("Group members of myGroup: " + groupMembers);

      String groupAccessUserGuid = registerNewUser("groupAccessUser");

      writeField(groupAccessUserGuid, "age", "43");
      writeField(groupAccessUserGuid, "hometown", "whoville");

      addToACL(groupAccessUserGuid, "hometown", groupGuid);

      try {
        result = readField(groupAccessUserGuid, "age", westyGuid);
        System.out.println("Result of read of groupAccessUser's age by westy is " + result);
      } catch (RuntimeException e) {
        System.out.println("Result of read of groupAccessUser's age by westy was correctly rejected.");
      }

      try {
        result = readField(groupAccessUserGuid, "hometown", westyGuid);
        System.out.println("Result of read of groupAccessUser's hometown by westy is " + result);
      } catch (RuntimeException e) {
        System.out.println("Result of read of groupAccessUser's hometown by westy was incorrectly rejected.");
      }


    } catch (RuntimeException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (IOException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (NoSuchAlgorithmException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (InvalidKeyException e) {
      GCRS.getLogger().severe(e.toString());
    } catch (SignatureException e) {
      GCRS.getLogger().severe(e.toString());
    }
  }

  /** 
   * Register a new username on the GCRS server. A guid is returned by the server.
   * Generates a public / private key pair which is saved in preferences and sent to the server with the username.
   * 
   * Query format: registerEntity?name=<userName>&publickey=<publickey> 
   * 
   * @param username 
   * @return guid
   * @throws IOException 
   * @throws NoSuchAlgorithmException  
   * 
   */
  public String registerNewUser(String username) throws IOException, NoSuchAlgorithmException {

    KeyPair keyPair = KeyPairGenerator.getInstance(Protocol.RASALGORITHM).generateKeyPair();
    saveKeyPairToPreferences(username, keyPair);

    PublicKey publicKey = keyPair.getPublic();
    byte[] publicKeyBytes = publicKey.getEncoded();
    String publicKeyString = Utils.toHex(publicKeyBytes);

    String command = createQuery(Protocol.REGISTERENTITY, Protocol.NAME, URIEncoderDecoder.quoteIllegal(username, ""), Protocol.PUBLICKEY, publicKeyString);
    String response = sendGetCommand(command);

    saveKeyPairToPreferences(response, keyPair);

    if (response.startsWith(Protocol.BADRESPONSE)) {
      throw (new RuntimeException("Bad response to command: " + command));
    } else {
      return response;
    }
  }

  /** 
   * Obtains the guid of the username from the GCRS server. 
   * 
   * Query format: lookupEntity?name=<userName> 
   * 
   * @param username 
   * @return guid
   * @throws IOException  
   * 
   */
  public String lookupUserGuid(String username) throws IOException {
    String command = createQuery(Protocol.LOOKUPENTITY, Protocol.NAME, URIEncoderDecoder.quoteIllegal(username, ""));
    String response = sendGetCommand(command);

    if (response.startsWith(Protocol.BADRESPONSE)) {
      throw (new RuntimeException("Bad response: " + response + " Command: " + command));
    } else {
      return response;
    }
  }

  /** 
   * Writes a key / value pair to the GCRS server for the given guid. 
   * Signs the query using the private key of the user associated with the guid.
   * 
   * Query format: insert?guid=<guid>&field=<field>&value=<value>&signature=<signature> 
   * 
   * @param guid 
   * @param field 
   * @param value 
   * @throws IOException 
   * @throws InvalidKeyException 
   * @throws NoSuchAlgorithmException 
   * @throws RuntimeException if the query is not accepted by the server.
   * @throws SignatureException  
   * 
   */
  public void writeField(String guid, String field, String value) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    String command = createAndSignQuery(guid, Protocol.INSERTONE, Protocol.GUID, guid, Protocol.FIELD, field, Protocol.VALUE, value);
    //String command = signMessage(guid, Protocol.INSERTONE + QUERYPREFIX + Protocol.GUID + VALSEP + guid + KEYSEP + Protocol.FIELD + VALSEP + URLEncoder.encode(field, "UTF-8") + KEYSEP + Protocol.VALUE + VALSEP + URLEncoder.encode(value, "UTF-8"));
    String response = sendGetCommand(command);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      throw (new RuntimeException("Bad response: " + response + " Command: " + command));
    }
  }

  /** 
   * Writes multiple key / value pair to the GCRS server for the given guid. 
   * Keys and values of the json parameter are formatted using the toString method of jsonObject.
   * Signs the query using the private key of the user associated with the guid.
   * 
   * Query format: insert?guid=<guid>&jsonstring=<jsonString>&signature=<signature> 
   * 
   * @param guid 
   * @param json 
   * @throws IOException 
   * @throws RuntimeException if the query is not accepted by the server.
   * @throws InvalidKeyException
   * @throws SignatureException 
   * @throws NoSuchAlgorithmException  
   * 
   */
  public void writeFields(String guid, String json) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    String command = createAndSignQuery(guid, Protocol.INSERT, Protocol.GUID, guid, Protocol.JSONSTRING, json);
    //String command = signMessage(guid, Protocol.INSERT + QUERYPREFIX + Protocol.GUID + VALSEP + guid + KEYSEP + Protocol.JSONSTRING + VALSEP + URLEncoder.encode(json, "UTF-8"));
    String response = sendGetCommand(command);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      throw (new RuntimeException("Bad response: " + response + " Command: " + command));
    }
  }

  /** 
   * Reads a single value for a key from the GCRS server or the given guid. The guid of the user attempting access is also needed.
   * Signs the query using the private key of the user associated with the guid.
   * 
   * Query format: lookup?guid=<guid>&field=<field>&reader=<readerguid>&signature=<signature>
   * @param guid 
   * @param field 
   * @param reader 
   * @return 
   * @throws RuntimeException if the query is not accepted by the server.
   * @throws IOException 
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException 
   * @throws SignatureException  
   */
  public String readField(String guid, String field, String reader) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    String command = createAndSignQuery(reader, Protocol.LOOKUP, Protocol.GUID, guid, Protocol.FIELD, field, Protocol.READER, reader);
    //String command = signMessage(reader, Protocol.LOOKUP + QUERYPREFIX + Protocol.GUID + VALSEP + guid + KEYSEP + Protocol.FIELD + VALSEP + URLEncoder.encode(field, "UTF-8") + KEYSEP + Protocol.READER + VALSEP + reader);
    String response = sendGetCommand(command);

    if (response.startsWith(Protocol.BADRESPONSE)) {
      throw (new RuntimeException("Bad response: " + response + " Command: " + command));
    } else if (response.startsWith(Protocol.UNKNOWNUSER)) {
      throw (new RuntimeException("Unknown user: " + response + " Command: " + command));
    } else {
      return response;
    }
  }

  /** 
   * Updates the access control list of the given user's field on the GCRS server to include the guid specified in the reader param.
   * The reader can be a guid of a user or a group guid or +ALL+ which means anyone can access the field.
   * The field can be also be +ALL+ which means all fields can be read by the reader.
   * Signs the query using the private key of the user associated with the guid.
   * 
   * Query format: aclAdd?guid=<guid>&field=<field>&reader=<allowedreaderguid>&signature=<signature> 
   * 
   * @param guid 
   * @param field 
   * @param reader 
   * @throws RuntimeException if the query is not accepted by the server.
   * @throws IOException 
   * @throws InvalidKeyException 
   * @throws NoSuchAlgorithmException 
   */
  public void addToACL(String guid, String field, String reader) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    String command = createAndSignQuery(guid, Protocol.ACLADD, Protocol.GUID, guid, Protocol.FIELD, field, Protocol.READER, reader);
    //String command = signMessage(guid, Protocol.ACLADD + QUERYPREFIX + Protocol.GUID + VALSEP + guid + KEYSEP + Protocol.FIELD + VALSEP + URLEncoder.encode(field, "UTF-8") + KEYSEP + Protocol.READER + VALSEP + reader);
    String response = sendGetCommand(command);

    if (!response.startsWith(Protocol.OKRESPONSE)) {
      throw (new RuntimeException("Bad response: " + response + " Command: " + command));
    }
  }

  /**
   * Creates a http query string from the given action string and a variable number of key and value pairs.
   * 
   * @param action
   * @param keysAndValues
   * @return the query string
   * @throws IOException
   */
  public String createQuery(String action, String... keysAndValues) throws IOException {
    String key;
    String value;
    StringBuilder result = new StringBuilder(action + QUERYPREFIX);

    for (int i = 0; i < keysAndValues.length; i = i + 2) {
      key = keysAndValues[i];
      value = keysAndValues[i + 1];
      result.append(URIEncoderDecoder.quoteIllegal(key, "") + VALSEP + URIEncoderDecoder.quoteIllegal(value, "") + (i + 2 < keysAndValues.length ? KEYSEP : ""));
    }
    return result.toString();
  }

  /** 
   * Creates a http query string from the given action string and a variable number of key and value pairs with a signature parameter.
   * The signature is generated from the query signed by the given guid. 
   * 
   * @param guid 
   * @param action 
   * @param keysAndValues 
   * @return the query string
   * @throws IOException
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws SignatureException  
   */
  public String createAndSignQuery(String guid, String action, String... keysAndValues) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    String key;
    String value;
    StringBuilder encodedString = new StringBuilder(action + QUERYPREFIX);
    StringBuilder unencodedString = new StringBuilder(action + QUERYPREFIX);

    // map over the leys and values to produce the query
    for (int i = 0; i < keysAndValues.length; i = i + 2) {
      key = keysAndValues[i];
      value = keysAndValues[i + 1];
      encodedString.append(URIEncoderDecoder.quoteIllegal(key, "") + VALSEP + URIEncoderDecoder.quoteIllegal(value, "") + (i + 2 < keysAndValues.length ? KEYSEP : ""));
      unencodedString.append(key + VALSEP + value + (i + 2 < keysAndValues.length ? KEYSEP : ""));
    }
    GCRS.getLogger().finer("Encoded: " + encodedString.toString());
    GCRS.getLogger().finer("Unencoded: " + unencodedString.toString());

    // generate the signature from the unencoded query
    String signature = signDigestOfMessage(guid, unencodedString.toString());
    // return the encoded query with the signature appended
    return encodedString.toString() + KEYSEP + Protocol.SIGNATURE + VALSEP + signature;
  }

  /** 
   * Signs a digest of a message using private key of the given guid. 
   * 
   * @param guid 
   * @param message 
   * @return a signed digest of the message string
   * @throws InvalidKeyException 
   * @throws NoSuchAlgorithmException
   * @throws SignatureException  
   */
  public String signDigestOfMessage(String guid, String message) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
    byte[] messageDigest = SHA1HashFunction.getInstance().hash(message.getBytes());

    KeyPair keyPair = getKeyPairFromPreferences(guid);
    //KeyPair keyPair = guidToKeyPair.get(guid);
    PrivateKey privateKey = keyPair.getPrivate();
    Signature instance = Signature.getInstance(Protocol.SIGNATUREALGORITHM);

    instance.initSign(privateKey);
    instance.update(messageDigest);
    byte[] signature = instance.sign();

    return Utils.toHex(signature);
  }

  /** 
   * Saves the public/private key pair to preferences for the given user. 
   * 
   * @param username 
   * @param keyPair 
   */
  public void saveKeyPairToPreferences(String username, KeyPair keyPair) {
    String publicString = Utils.toHex(keyPair.getPublic().getEncoded());
    String privateString = Utils.toHex(keyPair.getPrivate().getEncoded());
    userPreferencess.put(username + "-public", publicString);
    userPreferencess.put(username + "-private", privateString);
  }

  /** 
   * Retrieves the public/private key pair for the given user. 
   * 
   * @param username 
   * @return the keypair
   */
  public KeyPair getKeyPairFromPreferences(String username) {
    String publicString = userPreferencess.get(username + "-public", "");
    String privateString = userPreferencess.get(username + "-private", "");
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

  /**
   * Sends a HTTP get with given queryString to the host specified by the {@link HOST} field.
   * 
   * @param queryString 
   * @return result of get as a string
   */
  public String sendGetCommand(String queryString) {
    HttpURLConnection connection = null;
    OutputStreamWriter wr = null;
    BufferedReader rd = null;
    StringBuilder sb = null;

    URL serverAddress = null;

    try {
      String urlString = HOST + "/GCRS/" + queryString;
      GCRS.getLogger().finer("URL String = " + urlString);
      serverAddress = new URL(urlString);
      //set up out communications stuff
      connection = null;

      //Set up the initial connection
      connection = (HttpURLConnection) serverAddress.openConnection();
      connection.setRequestMethod("GET");
      connection.setDoOutput(true);
      connection.setReadTimeout(10000);

      connection.connect();

      //get the output stream writer and write the output to the server
      //not needed in this example
      //wr = new OutputStreamWriter(connection.getOutputStream());
      //wr.write("");
      //wr.flush();

      //read the result from the server
      rd = new BufferedReader(new InputStreamReader(connection.getInputStream()));
      sb = new StringBuilder();

      String response = rd.readLine(); // we only expect one line to be sent
      if (response != null) {
        return response;
      } else {
        throw (new RuntimeException("No response to command: " + queryString));
      }
    } catch (MalformedURLException e) {
      e.printStackTrace();
    } catch (ProtocolException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      //close the connection, set all objects to null
      connection.disconnect();
      rd = null;
      sb = null;
      wr = null;
      connection = null;
    }
    return "";
  }
  
  public static String Version = "$Revision$";
  
}
