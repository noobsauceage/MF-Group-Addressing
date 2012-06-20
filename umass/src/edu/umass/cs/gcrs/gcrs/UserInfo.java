package edu.umass.cs.gcrs.gcrs;

/**
 * Stores the username, GUID and public key for a user
 * 
 * @author westy
 */
public class UserInfo {

  String userName;
  String guid;
  String publicKey;

  public UserInfo(String userName, String guid, String publicKey) {
    this.userName = userName;
    this.guid = guid;
    this.publicKey = publicKey;
  }

  public String getUserName() {
    return userName;
  }
  
  public String getGuid() {
    return guid;
  }

  public String getPublicKey() {
    return publicKey;
  }

  @Override
  public String toString() {
    return "UserInfo{" + "userName=" + userName + ", guid=" + guid + ", publicKey=" + publicKey + '}';
  }
 
}
