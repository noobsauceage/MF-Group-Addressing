package edu.umass.cs.gcrs.server;

import edu.umass.cs.gcrs.database.GroupTableEntry;
import edu.umass.cs.gcrs.gcrs.GroupInfo;
import edu.umass.cs.gcrs.database.GroupTable;
import edu.umass.cs.gcrs.database.AclTable;
import edu.umass.cs.gcrs.database.AclTableEntry;
import edu.umass.cs.gcrs.database.MainTable;
import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.SHA1HashFunction;
import edu.umass.cs.gcrs.gcrs.UserInfo;
import edu.umass.cs.gcrs.utilities.Utils;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import static edu.umass.cs.gcrs.server.Defs.*;

/**
 * Implements the GCRS server protocol for both the HTTP and line parsing server.
 * 
 * @author westy
 */
public class Protocol {

  public static String Version = "$Revision$";
  public final static String REGISTERENTITY = "registerEntity";
  public final static String LOOKUPENTITY = "lookupEntity";
  public final static String INSERTONE = "insertOne";
  public final static String INSERT = "insert";
  public final static String LOOKUP = "lookup";
  public final static String LOOKUPALL = "lookupAll";
  public final static String ACLADD = "aclAdd";
  public final static String ACLREMOVE = "aclRemove";
  public final static String ACL = "acl";
  public final static String ACLALL = "aclAll";
  public final static String CREATEGROUP = "createGroup";
  public final static String LOOKUPGROUP = "lookupGroup";
  public final static String ADDTOGROUP = "addToGroup";
  public final static String REMOVEFROMGROUP = "removeFromGroup";
  public final static String GETGROUPMEMBERS = "getGroupMembers";
  public final static String HELP = "help";
  // demo commands (not accesible in "public" version")
  public final static String DEMO = "demo";
  public final static String CLEAR = "clear";
  public final static String DUMP = "dump";
  //
  public final static String OKRESPONSE = "+OK+";
  public final static String NULLRESPONSE = "+EMPTY+";
  public final static String BADRESPONSE = "+NO+";
  public final static String UNKNOWNUSER = "+BADUSER+";
  public final static String UNKNOWNGROUP = "+BADGROUP+";
  public final static String ALLFIELDS = "+ALL+";
  public final static String ALLUSERS = "+ALL+";
  //
  public static final String RASALGORITHM = "RSA";
  public static final String SIGNATUREALGORITHM = "SHA1withRSA";
  private final static String NEWLINE = System.getProperty("line.separator");
  // Fields for HTTP get queries
  public final static String NAME = "name";
  public final static String GUID = "guid";
  public final static String READER = "reader";
  public final static String FIELD = "field";
  public final static String VALUE = "value";
  public final static String JSONSTRING = "jsonstring";
  public final static String GROUP = "group";
  public final static String PUBLICKEY = "publickey";
  public final static String SIGNATURE = "signature";
  public final static String PASSKEY = "passkey";
  public final static String TABLE = "table";
  //
  private boolean demoMode = false;
  private MainTable mainTable = MainTable.getInstance();
  private AclTable aclTable = AclTable.getInstance();
  private GroupTable groupTable = GroupTable.getInstance();
  //
  // help string for HTTP query

  private String getHelpString(String hostString) {
    String urlPrefix = "http://" + hostString + "/GCRS/";
    String main =
            "Commands are sent as HTTP GET queries." + NEWLINE + NEWLINE
            + "Commands:" + NEWLINE
            + urlPrefix + HELP + NEWLINE
            + "  Returns this help message." + NEWLINE + NEWLINE
            + urlPrefix + REGISTERENTITY + QUERYPREFIX + NAME + VALSEP + "<userName>" + KEYSEP + PUBLICKEY + VALSEP + "<publickey>" + NEWLINE
            + "  Records the userName which is a human readable name for the user and the supplied publickey. Returns a guid." + NEWLINE + NEWLINE
            //+ urlPrefix + REGISTERENTITY + QUERYPREFIX + NAME + VALSEP + "<userName>" + KEYSEP + GUID + VALSEP + "<guid>" + KEYSEP + PUBLICKEY + VALSEP + "<publickey>" + NEWLINE
            //+ "  Records the userName which is a human readable name for the user, the supplied guid (which is usually a hash of the publickey) and the publickey." + NEWLINE + NEWLINE
            + urlPrefix + LOOKUPENTITY + QUERYPREFIX + NAME + VALSEP + "<userName>" + NEWLINE
            + "  Returns the guid registered for this userName. Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            //+ urlPrefix + INSERTONE + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + FIELD + VALSEP + "<field>" + KEYSEP + VALUE + VALSEP + "<value>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            //+ "  Adds a key value pair to the database for the given user. The signature is a digest of the entire command signed by the private key of the user. "
            //+ "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + INSERT + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + JSONSTRING + VALSEP + "<jsonString>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            + "  Adds all the key value pairs in the jsonString to the database for the given user. The signature is a digest of the query (everything AFTER the " + urlPrefix + ") signed by the private key of the user. "
            + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + LOOKUP + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + FIELD + VALSEP + "<field>" + KEYSEP + READER + VALSEP + "<readerguid>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            + "  Returns one key value pair from the database for the given guid after authenticating that the readerguid (user making request) has access authority. "
            + "Specify " + ALLFIELDS + " as the <field> to return all fields. "
            + "Signature as above for the user making the request. "
            + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            //+ urlPrefix + LOOKUPALL + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + READER + VALSEP + "<readerguid>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            //+ "  Returns all the key value pairs from the database for the given guid after authenticating that the readerguid (user making request) has access authority. "
            //+ "Signature as above for the user making the request. "
            //+ "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + ACLADD + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + FIELD + VALSEP + "<field>" + KEYSEP + READER + VALSEP + "<allowedreaderguid>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            + "  Updates the access control list of the given user's field to include the allowedreader. " + NEWLINE
            + "allowedreader can be a guid of a user or a group or " + ALLUSERS + " which means anyone." + NEWLINE
            + "field can be also be " + ALLFIELDS + " which means all fields can be read by the allowedreader" + NEWLINE
            + "The signature as above is a digest of the query signed by the private key of the user. " + NEWLINE
            + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + ACLREMOVE + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + FIELD + VALSEP + "<field>" + KEYSEP + READER + VALSEP + "<allowedreaderguid>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            + "  Updates the access control list of the given user's field to remove the allowedreader. Signature as above. "
            + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + ACL + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + FIELD + VALSEP + "<field>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            + "  Returns the access control list for a user's field. Signature as above. "
            + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + ACLALL + QUERYPREFIX + GUID + VALSEP + "<guid>" + KEYSEP + SIGNATURE + VALSEP + "<signature>" + NEWLINE
            + "  Returns the entire access control list. Signature as above. "
            + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + CREATEGROUP + QUERYPREFIX + NAME + VALSEP + "<groupName>" + KEYSEP + PUBLICKEY + VALSEP + "<publickey>" + NEWLINE
            + "  Records the groupName which is a human readable name for the group and the supplied publickey. Returns a guid." + NEWLINE + NEWLINE
            + urlPrefix + LOOKUPGROUP + QUERYPREFIX + NAME + VALSEP + "<groupName>" + NEWLINE
            + "  Returns the guid registered for this group. Returns " + UNKNOWNGROUP + " if the userName has not been registered." + NEWLINE + NEWLINE
            + urlPrefix + ADDTOGROUP + QUERYPREFIX + GROUP + VALSEP + "<groupGuid>" + KEYSEP + GUID + VALSEP + "<guid>" + NEWLINE
            + "  Adds the guid to the group specfied by groupGuid." + NEWLINE + NEWLINE
            + urlPrefix + REMOVEFROMGROUP + QUERYPREFIX + GROUP + VALSEP + "<groupGuid>" + KEYSEP + GUID + VALSEP + "<guid>" + NEWLINE
            + "  Removes the guid from the group specfied by groupGuid." + NEWLINE + NEWLINE
            + urlPrefix + GETGROUPMEMBERS + QUERYPREFIX + GROUP + VALSEP + "<groupGuid>" + NEWLINE
            + "  Returns the members of the group formatted as a JSON Array." + NEWLINE + NEWLINE;

    String demo = NEWLINE + NEWLINE + urlPrefix + DEMO + QUERYPREFIX + PASSKEY + VALSEP + "<value>" + NEWLINE
            + "  Enters demo mode if supplied with the correct passkey. If passkey is 'off' turns demo mode off." + NEWLINE + NEWLINE
            + urlPrefix + CLEAR + NEWLINE
            + "  [ONLY IN DEMO MODE] Clears the database." + NEWLINE + NEWLINE
            + urlPrefix + DUMP + QUERYPREFIX + TABLE + VALSEP + "[table | acl | group]" + NEWLINE
            + "  [ONLY IN DEMO MODE] Returns the contents of the named table." + NEWLINE + NEWLINE;

    String post = NEWLINE + "Complex data fields can be read and written using JSON." + NEWLINE
            + "Commands that don't return anything return the string " + OKRESPONSE + " if they are accepted." + NEWLINE
            + "Commands that cannot be processed return the string " + BADRESPONSE + " with an optional error message appended." + NEWLINE;
    return main + (demoMode ? demo : "") + post;
  }
  //
  // help string for line based server
  private final static String HELPSTRING = "Commands should be sent to the server as clear text strings with spaces as separators. They are terminated with a newline." + NEWLINE
          + "The syntax is: <keyword> <argument1> <argument2> ... <argumentn> <signature*> where the signature is not required for some commands." + NEWLINE
          + "The first argument is a keyword specifying the command followed by arguments separated by spaces." + NEWLINE
          + "If a signature is required it is the digest of the entire command (keyword and arguments) appended onto the command." + NEWLINE + NEWLINE
          + "Commands:" + NEWLINE
          + REGISTERENTITY + " <userName> <publickey>" + NEWLINE
          + "  Records the userName which is a human readable name for the user. Users supplies the publickey. Returns a guid." + NEWLINE + NEWLINE
          + REGISTERENTITY + " <userName> <guid> <publickey>" + NEWLINE
          + "  Records the userName which is a human readable name for the user. Users supplies a guid (which is usually a hash of the publickey) and the publickey." + NEWLINE + NEWLINE
          + LOOKUPENTITY + " <userName>" + NEWLINE
          + "  Returns the guid registered for this userName. Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + INSERTONE + " <guid> <field> <value> <signature>" + NEWLINE
          + "  Adds a key value pair to the database for the given user. The signature is a digest of the entire command signed by the private key of the user. "
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + INSERT + " <guid> <jsonString> <signature>" + NEWLINE
          + "  Adds all the key value pairs in the jsonString to the database for the given user. Signature as above. "
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + LOOKUP + " <guid> <field> <readerguid> <signature>" + NEWLINE
          + "  Returns one key value pair from the database for the given guid after authenticating that the readerguid (user making request) has access authority. "
          + "Signature as above for the user making the request."
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + LOOKUPALL + " <guid> <readerguid> <signature>" + NEWLINE
          + "  Returns all the key value pairs from the database for the given guid after authenticating that the readerguid (user making request) has access authority. "
          + "Signature as above for the user making the request."
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + ACLADD + " <guid> <field> <allowedreaderguid> <signature>" + NEWLINE
          + "  Updates the access control list of the given user's field to include the allowedreader. The signature as above is a digest of the entire command "
          + "signed by the private key of the user."
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + ACLREMOVE + " <guid> <field> <allowedreaderguid> <signature>" + NEWLINE
          + "  Updates the access control list of the given user's field to remove the allowedreader. Signature as above. "
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + ACL + " <guid> <field> <signature>" + NEWLINE
          + "  Returns the access control list for a user's field. Signature as above. "
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + ACLALL + " <guid> <signature>" + NEWLINE
          + "  Returns the entire access control list. Signature as above. "
          + "Returns " + UNKNOWNUSER + " if the userName has not been registered." + NEWLINE + NEWLINE
          + "Complex data fields can be read and written using JSON." + NEWLINE
          + "Commands that don't return anything return the string " + OKRESPONSE + " if they are accepted." + NEWLINE
          + "Commands that cannot be processed return the string " + BADRESPONSE + " with an optional error message appended." + NEWLINE;

  private UserInfo getUserInfo(String guid) {
    AclTableEntry result = aclTable.lookupFromGuid(guid);
    if (result != null) {
      return result.getUserInfo();
    } else {
      return null;
    }
  }

  private GroupInfo getGroupInfo(String guid) {
    GroupTableEntry result = groupTable.lookupFromGuid(guid);
    if (result != null) {
      return result.getGroupInfo();
    } else {
      return null;
    }
  }

  /** 
   * RegisterEntity(name, ...) – Name is human readable name of entity(device, owner, app/service, context, group, etc.)
   * 
   * @param userName
   * @param guid
   * @param publicKey
   * @return GUID
   */
  public String processRegisterUser(String userName, String publicKey) {
    if (aclTable.findUser(userName) == null) {
      byte[] publicKeyDigest = SHA1HashFunction.getInstance().hash(publicKey.getBytes());
      String guid = Utils.toHex(publicKeyDigest);
      aclTable.addUser(new UserInfo(userName, guid, publicKey));
      return guid;
    } else {
      return BADRESPONSE;
    }
  }

  public String processRegisterUserWithGuid(String userName, String guid, String publicKey) {
    if (aclTable.findUser(userName) == null) {
      aclTable.addUser(new UserInfo(userName, guid, publicKey));
      return OKRESPONSE;
    } else {
      return BADRESPONSE;
    }
  }

  public String processLookup(String userName) {
    UserInfo userInfo = aclTable.findUser(userName);
    if (userInfo != null) {
      return userInfo.getGuid();
    } else {
      return UNKNOWNUSER;
    }
  }

  public String processWrite(String guid, String field, String value, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(userInfo, signature, message)) {
      mainTable.update(userInfo.getGuid(), field, value);
      return OKRESPONSE;
    } else {
      return BADRESPONSE;
    }
  }

  public String processWriteAll(String guid, String jsonString, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(userInfo, signature, message)) {
      mainTable.updateFromObject(userInfo.getGuid(), jsonString);
      return OKRESPONSE;
    } else {
      return BADRESPONSE;
    }
  }

  public String processRead(String guid, String field, String reader, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo, readerInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if ((readerInfo = getUserInfo(reader)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(readerInfo, signature, message) && verifyAccess(userInfo, field, readerInfo)) {
      if (ALLFIELDS.equals(field)) {
        return mainTable.lookup(userInfo.getGuid()).toString();
      } else {
        return mainTable.lookup(userInfo.getGuid(), field);
      }
    } else {
      return BADRESPONSE;
    }
  }

  public String processReadAll(String guid, String reader, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo, readerInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if ((readerInfo = getUserInfo(reader)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(readerInfo, signature, message) && verifyAccess(userInfo, readerInfo)) {
      return mainTable.lookup(userInfo.getGuid()).toString();
    } else {
      return BADRESPONSE;
    }
  }

  public String processAclAdd(String guid, String field, String reader, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo, readerInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(userInfo, signature, message)) {
      aclTable.add(userInfo, field, reader);
      return OKRESPONSE;
    } else {
      return BADRESPONSE;
    }
  }

  public String processAclRemove(String guid, String field, String reader, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo, readerInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(userInfo, signature, message)) {
      aclTable.remove(userInfo, field, reader);
      return OKRESPONSE;
    } else {
      return BADRESPONSE;
    }
  }

  public String processAcl(String guid, String field, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo, readerInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(userInfo, signature, message)) {
      JSONArray list = new JSONArray();
      Set values = aclTable.lookup(userInfo, field);
      list.addAll(values);
      return list.toString();
    } else {
      return BADRESPONSE;
    }
  }

  public String processAclAll(String guid, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    UserInfo userInfo, readerInfo;
    if ((userInfo = getUserInfo(guid)) == null) {
      return UNKNOWNUSER;
    }
    if (verifySignature(userInfo, signature, message)) {
      JSONObject result = aclTable.lookup(userInfo);
      if (result != null) {
        return result.toString();
      } else {
        return new JSONObject().toString();
      }
    } else {
      return BADRESPONSE;
    }
  }

  public String processCreateGroup(String groupName, String publicKey) {
    if (groupTable.findGroup(groupName) == null) {
      byte[] publicKeyDigest = SHA1HashFunction.getInstance().hash(publicKey.getBytes());
      String guid = Utils.toHex(publicKeyDigest);
      groupTable.addGroup(new GroupInfo(groupName, guid, publicKey));
      return guid;
    } else {
      return BADRESPONSE;
    }
  }

  public String processLookupGroup(String groupname) {
    GroupInfo groupInfo = groupTable.findGroup(groupname);
    if (groupInfo != null) {
      return groupInfo.getGuid();
    } else {
      return UNKNOWNUSER;
    }
  }

  public String processAddToGroup(String group, String guid) {
    GroupInfo groupInfo;
    if ((groupInfo = getGroupInfo(group)) == null) {
      return UNKNOWNGROUP;
    }
    groupTable.add(groupInfo, guid);
    return OKRESPONSE;
  }

  public String processRemoveFromGroup(String group, String guid) {
    GroupInfo groupInfo;
    if ((groupInfo = getGroupInfo(group)) == null) {
      return UNKNOWNGROUP;
    }
    groupTable.remove(groupInfo, guid);
    return OKRESPONSE;
  }

  public String processGetGroupMembers(String group) {
    GroupInfo groupInfo;
    if ((groupInfo = getGroupInfo(group)) == null) {
      return UNKNOWNGROUP;
    }
    return groupTable.lookup(groupInfo).toString();
  }

  public String processDemo(String passkey, String inputLine) {
    if ("umass".equals(passkey)) {
      demoMode = true;
      return OKRESPONSE;
    } else if ("off".equals(passkey)) {
      demoMode = false;
      return OKRESPONSE;
    } else {
      return BADRESPONSE + " - Don't understand " + DEMO + QUERYPREFIX + inputLine;
    }
  }

  public String processDump(String argument, String inputLine) {
    if (demoMode) {
      if ("table".equals(argument)) {
        return mainTable.dump();
      } else if ("acl".equals(argument)) {
        return aclTable.dump();
      } else if ("group".equals(argument)) {
        return groupTable.dump();
      }
    }
    return BADRESPONSE + " - Don't understand " + DUMP + QUERYPREFIX + inputLine;
  }

  public String processClear(String inputLine) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    if (demoMode) {
      mainTable.resetTable();
      aclTable.resetTable();
      groupTable.resetTable();
      return OKRESPONSE;
    } else {
      return BADRESPONSE + " - Don't understand " + CLEAR + QUERYPREFIX + inputLine;
    }
  }

  /** process queries for the http service **/
  public String processQuery(String action, String queryString) {
    String fullString = action + QUERYPREFIX + queryString; // for signature check
    Map<String, String> queryMap = Utils.parseURIQueryString(queryString);
    //String action = queryMap.get(ACTION);
    try {
      // HELP
      if (HELP.equals(action)) {
        return getHelpString(GcrsHttpServer.hostName + (GcrsHttpServer.address != 80 ? (":" + GcrsHttpServer.address) : ""));
      } else if (REGISTERENTITY.equals(action) && queryMap.keySet().containsAll(Arrays.asList(NAME, GUID, PUBLICKEY))) {
        // syntax: register userName guid public_key
        String userName = queryMap.get(NAME);
        String guid = queryMap.get(GUID);
        String publicKey = queryMap.get(PUBLICKEY);
        return processRegisterUserWithGuid(userName, guid, publicKey);
      } else if (REGISTERENTITY.equals(action) && queryMap.keySet().containsAll(Arrays.asList(NAME, PUBLICKEY))) {
        // syntax: register userName guid public_key
        String userName = queryMap.get(NAME);
        String publicKey = queryMap.get(PUBLICKEY);
        return processRegisterUser(userName, publicKey);
        // LOOKUP
      } else if (LOOKUPENTITY.equals(action) && queryMap.keySet().containsAll(Arrays.asList(NAME))) {
        // syntax: lookup userName
        String userName = queryMap.get(NAME);
        return processLookup(userName);
        //WRITE
      } else if (INSERTONE.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, FIELD, VALUE, SIGNATURE))) {
        //} else if (WRITE.equals(action) && tokens.length == 5) {
        // Update a single value
        // syntax: write guid field value signature 
        String guid = queryMap.get(GUID);
        String field = queryMap.get(FIELD);
        String value = queryMap.get(VALUE);
        String signature = queryMap.get(SIGNATURE);
        return processWrite(guid, field, value, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        // WRITEALL
        // TODO verify that the WRITEALL command works
      } else if (INSERT.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, JSONSTRING, SIGNATURE))) {
        // } else if (WRITEALL.equals(action) && tokens.length == 4) {
        // Update a bunch of key value pairs from a passed in JSON object
        // syntax: writeAll guid jsonString signature 
        String guid = queryMap.get(GUID);
        String jsonString = queryMap.get(JSONSTRING);
        String signature = queryMap.get(SIGNATURE);
        return processWriteAll(guid, jsonString, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        // READ
      } else if (LOOKUP.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, FIELD, READER, SIGNATURE))) {
        // Read one field
        // syntax: guid field reader signature
        String guid = queryMap.get(GUID);
        String field = queryMap.get(FIELD);
        String reader = queryMap.get(READER);
        String signature = queryMap.get(SIGNATURE);
        return processRead(guid, field, reader, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        //READALL
      } else if (LOOKUPALL.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, READER, SIGNATURE))) {
        // Read all fields
        // syntax: readAll guid reader signature
        String guid = queryMap.get(GUID);
        String reader = queryMap.get(READER);
        String signature = queryMap.get(SIGNATURE);
        return processReadAll(guid, reader, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        // ACLADD
      } else if (ACLADD.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, FIELD, READER, SIGNATURE))) {
        // syntax: aclAdd hash field allowedreader signature
        String guid = queryMap.get(GUID);
        String field = queryMap.get(FIELD);
        String reader = queryMap.get(READER);
        String signature = queryMap.get(SIGNATURE);
        return processAclAdd(guid, field, reader, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        // ACLREMOVE
      } else if (ACLREMOVE.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, FIELD, READER, SIGNATURE))) {
        // syntax: aclRemove guid field allowedreader signature
        String guid = queryMap.get(GUID);
        String field = queryMap.get(FIELD);
        String reader = queryMap.get(READER);
        String signature = queryMap.get(SIGNATURE);
        return processAclRemove(guid, field, reader, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        // ACL
      } else if (ACL.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, FIELD, SIGNATURE))) {
        // show the acl list for user's field
        // syntax: acl guid field signature
        String guid = queryMap.get(GUID);
        String field = queryMap.get(FIELD);
        String signature = queryMap.get(SIGNATURE);
        return processAcl(guid, field, signature, removeSignature(fullString, KEYSEP + SIGNATURE + VALSEP + signature));
        // ACLALL
      } else if (ACLALL.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GUID, SIGNATURE))) {
        // show the acl list for a user
        // syntax: aclAll guid signature
        String guid = queryMap.get(GUID);
        String signature = queryMap.get(SIGNATURE);
        return processAclAll(guid, signature, queryString);
      } else if (CREATEGROUP.equals(action) && queryMap.keySet().containsAll(Arrays.asList(NAME, PUBLICKEY))) {
        // syntax: register userName guid public_key
        String groupName = queryMap.get(NAME);
        String publicKey = queryMap.get(PUBLICKEY);
        return processCreateGroup(groupName, publicKey);
      } else if (LOOKUPGROUP.equals(action) && queryMap.keySet().containsAll(Arrays.asList(NAME))) {
        // syntax: lookup userName
        String groupName = queryMap.get(NAME);
        return processLookupGroup(groupName);
        //WRITE
      } else if (ADDTOGROUP.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GROUP, GUID))) {
        String group = queryMap.get(GROUP);
        String guid = queryMap.get(GUID);
        return processAddToGroup(group, guid);
      } else if (REMOVEFROMGROUP.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GROUP, GUID))) {
        String group = queryMap.get(GROUP);
        String guid = queryMap.get(GUID);
        return processRemoveFromGroup(group, guid);
      } else if (GETGROUPMEMBERS.equals(action) && queryMap.keySet().containsAll(Arrays.asList(GROUP))) {
        String group = queryMap.get(GROUP);
        return processGetGroupMembers(group);
        // DEMO
      } else if (DEMO.equals(action) && queryMap.keySet().containsAll(Arrays.asList(PASSKEY))) {
        return processDemo(queryMap.get(PASSKEY), queryString);
        // CLEAR
      } else if (CLEAR.equals(action)) {
        return processClear(queryString);
      } else if (DUMP.equals(action) && queryMap.keySet().containsAll(Arrays.asList(TABLE))) {
        return processDump(queryMap.get(TABLE), queryString);
      } else {
        return BADRESPONSE + " - Don't understand " + action + QUERYPREFIX + queryString;
      }
    } catch (NoSuchAlgorithmException e) {
      return BADRESPONSE + " " + e;
    } catch (InvalidKeySpecException e) {
      return BADRESPONSE + " " + e;
    } catch (SignatureException e) {
      return BADRESPONSE + " " + e;
    } catch (InvalidKeyException e) {
      return BADRESPONSE + " " + e;
    }
  }

  /** process queries for the socket-based service **/
  public String processLineInput(String inputLine) {
    GCRS.getLogger().fine("Read " + inputLine);
    String[] tokens = inputLine.split(" ");
    try {
      // HELP
      if (HELP.equals(tokens[0])) {
        return HELPSTRING;
        // RegisterEntity
      } else if (REGISTERENTITY.equals(tokens[0]) && tokens.length == 3) {
        // syntax: RegisterEntity userName public_key
        String userName = tokens[1];
        String publicKey = tokens[2];
        return processRegisterUser(userName, publicKey);
        // RegisterEntity
      } else if (REGISTERENTITY.equals(tokens[0]) && tokens.length == 4) {
        // syntax: RegisterEntity userName guid public_key
        String userName = tokens[1];
        String guid = tokens[2];
        String publicKey = tokens[3];
        return processRegisterUserWithGuid(userName, guid, publicKey);
        // LOOKUP
      } else if (LOOKUPENTITY.equals(tokens[0]) && tokens.length == 2) {
        // syntax: lookupEntity userName
        // returns: guid
        String userName = tokens[1];
        return processLookup(userName);
        //INSERT
      } else if (INSERT.equals(tokens[0]) && tokens.length >= 4) {
        // } else if (WRITEALL.equals(tokens[0]) && tokens.length == 4) {
        // Update a bunch of key value pairs from a passed in JSON object
        // syntax: insert guid jsonString signature 
        String guid = tokens[1];
        int length = tokens.length;
        StringBuilder result = new StringBuilder();
        for (int n = 2; n < length - 1; n++) {
          result.append(tokens[n]);
          result.append(" ");
        }
        if (result.length() > 0) { // trim last space
          result.setLength(result.length() - 1);
        }
        String jsonString = result.toString();
        String signature = tokens[length - 1];
        return processWriteAll(guid, jsonString, signature, removeSignature(inputLine, " " + signature));
        // READ
      } else if (INSERTONE.equals(tokens[0]) && tokens.length >= 5) {
        // syntax: write guid field value signature
        //} else if (WRITE.equals(tokens[0]) && tokens.length == 5) {
        // Update a single value 
        // !!! special handling for spaces in value  
        String guid = tokens[1];
        String field = tokens[2];
        int length = tokens.length;
        StringBuilder result = new StringBuilder();
        for (int n = 3; n < length - 1; n++) {
          result.append(tokens[n]);
          result.append(" ");
        }
        if (result.length() > 0) { // trim last space
          result.setLength(result.length() - 1);
        }
        String value = result.toString();
        String signature = tokens[length - 1];
        return processWrite(guid, field, value, signature, removeSignature(inputLine, " " + signature));
        // WRITEALL
        // TODO verify that the WRITEALL command works
      } else if (LOOKUP.equals(tokens[0]) && tokens.length == 5) {
        // Read one field
        // syntax: guid field reader signature
        String guid = tokens[1];
        String field = tokens[2];
        String reader = tokens[3];
        String signature = tokens[4];
        return processRead(guid, field, reader, signature, removeSignature(inputLine, " " + signature));
        //READALL

      } else if (ACLADD.equals(tokens[0]) && tokens.length == 5) {
        // syntax: aclAdd hash field allowedreader signature
        String guid = tokens[1];
        String field = tokens[2];
        String reader = tokens[3];
        String signature = tokens[4];
        return processAclAdd(guid, field, reader, signature, removeSignature(inputLine, " " + signature));
        // ACLREMOVE
      } else if (ACLREMOVE.equals(tokens[0]) && tokens.length == 5) {
        // syntax: aclRemove guid field allowedreader signature
        String guid = tokens[1];
        String field = tokens[2];
        String reader = tokens[3];
        String signature = tokens[4];
        return processAclRemove(guid, field, reader, signature, removeSignature(inputLine, " " + signature));
        // ACL
      } else if (ACL.equals(tokens[0]) && tokens.length == 4) {
        // show the acl list for user's field
        // syntax: acl guid field signature
        String guid = tokens[1];
        String field = tokens[2];
        String signature = tokens[3];
        return processAcl(guid, field, signature, removeSignature(inputLine, " " + signature));
        // ACLALL
      } else if (ACLALL.equals(tokens[0]) && tokens.length == 3) {
        // show the acl list for a user
        // syntax: aclAll guid signature
        String guid = tokens[1];
        String signature = tokens[2];
        return processAclAll(guid, signature, removeSignature(inputLine, " " + signature));
        // DEMO
      } else if (DEMO.equals(tokens[0]) && tokens.length == 2) {
        return processDemo(tokens[1], inputLine);
        // CLEAR
      } else if (CLEAR.equals(tokens[0])) {
        return processClear(inputLine);
      } else if (DUMP.equals(tokens[0]) && tokens.length == 2) {
        return processDump(tokens[1], inputLine);
      } else {
        return BADRESPONSE + " - Don't understand " + inputLine;
      }
    } catch (NoSuchAlgorithmException e) {
      return BADRESPONSE + " " + e;
    } catch (InvalidKeySpecException e) {
      return BADRESPONSE + " " + e;
    } catch (SignatureException e) {
      return BADRESPONSE + " " + e;
    } catch (InvalidKeyException e) {
      return BADRESPONSE + " " + e;
    }
  }

  private boolean verifySignature(UserInfo userInfo, String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
    if (demoMode) {
      return true;
    }
    //String message = inputLine.substring(0, inputLine.lastIndexOf(signature));
    byte[] messageDigest = SHA1HashFunction.getInstance().hash(message.getBytes());

    byte[] encodedPublicKey = Utils.hexStringToByteArray(userInfo.getPublicKey());
    KeyFactory keyFactory = KeyFactory.getInstance(RASALGORITHM);
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

    Signature sig = Signature.getInstance(Protocol.SIGNATUREALGORITHM);
    sig.initVerify(publicKey);
    sig.update(messageDigest);
    boolean result = sig.verify(Utils.hexStringToByteArray(signature));
    GCRS.getLogger().fine("User " + userInfo.getUserName() + (result ? " verified " : " NOT verified ") + "as author of message " + message);
    return result;
  }

  private boolean verifyAccess(UserInfo contectInfo, UserInfo readerInfo) {
    return verifyAccess(contectInfo, ALLFIELDS, readerInfo);
  }

  private boolean verifyAccess(UserInfo userInfo, String field, UserInfo readerInfo) {
    if (userInfo.getGuid().equals(readerInfo.getGuid())) {
      return true; // can always read your own stuff
    } else {
      //AclTable acl = AclTable.getInstance();
      Set<String> allowedusers = aclTable.lookup(userInfo, field);
      GCRS.getLogger().finer(userInfo.getUserName() + " allowed users of " + field + " : " + allowedusers);
      //if (allowedusers.contains(readerInfo.getGuid()) || allowedusers.contains(ALLUSERS)) {
      if (checkAllowedUsers(readerInfo.getGuid(), allowedusers)) {
        GCRS.getLogger().fine("User " + readerInfo.getUserName() + " allowed to access user " + userInfo.getUserName() + "'s " + field + " field");
        return true;
      }
      // otherwise find any users that can access all of the fields
      allowedusers = aclTable.lookup(userInfo, ALLFIELDS);
      //if (allowedusers.contains(readerInfo.getGuid()) || allowedusers.contains(ALLUSERS)) {
      if (checkAllowedUsers(readerInfo.getGuid(), allowedusers)) {
        GCRS.getLogger().fine("User " + readerInfo.getUserName() + " allowed to access all of user " + userInfo.getUserName() + "'s fields");
        return true;
      }
    }
    GCRS.getLogger().fine("User " + readerInfo.getUserName() + " NOT allowed to access user " + userInfo.getUserName() + "'s " + field + " field");
    return false;
  }

  private boolean checkAllowedUsers(String guid, Set<String> allowedusers) {
    if (allowedusers.contains(guid)) {
      return true;
    } else if (allowedusers.contains(ALLUSERS)) {
      return true;
    } else {
      // map over the allowedusers and see if any of them are groups that the user belongs to
      for (String potentialGroupGuid : allowedusers) {
        GroupTableEntry entry = groupTable.lookupFromGuid(potentialGroupGuid);
        if (entry != null && entry.getJsonArray().contains(guid)) {
          return true;
        }
      }
      return false;
    }
  }

  private String removeSignature(String fullString, String fullSignatureField) {
    GCRS.getLogger().finer("fullstring = " + fullString + " fullSignatureField = " + fullSignatureField);
    String result = fullString.substring(0, fullString.lastIndexOf(fullSignatureField));
    GCRS.getLogger().finer("result = " + result);
    return result;
  }
}
