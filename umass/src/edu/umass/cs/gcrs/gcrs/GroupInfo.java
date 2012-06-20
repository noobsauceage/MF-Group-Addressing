package edu.umass.cs.gcrs.gcrs;

/**
 * Stores the username, GUID and public key for a user
 * 
 * @author westy
 */
public class GroupInfo {

  String groupName;
  String guid;
  String publicKey;

  public GroupInfo(String groupName, String guid, String publicKey) {
    this.groupName = groupName;
    this.guid = guid;
    this.publicKey = publicKey;
  }

  public String getGroupName() {
    return groupName;
  }

  public String getGuid() {
    return guid;
  }

  public String getPublicKey() {
    return publicKey;
  }

  @Override
  public String toString() {
    return "GroupInfo{" + "groupName=" + groupName + ", guid=" + guid + ", publicKey=" + publicKey + '}';
  }
 
}
