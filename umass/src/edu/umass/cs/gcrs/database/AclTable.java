package edu.umass.cs.gcrs.database;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.UserInfo;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * The Access Control Table (AclTable) stores information about a user that allows control of the users fields.
 * It is a frontend to a mySQL database. Stored in each record are the human readable username, the user's GUID 
 * which is the hash of the user's public-key and the public-key itself. 
 * 
 * The jsonobject contains the key and value pairs that determine user access.
 * Each key is the name of field and the value is a list of users that can access that field.
 * 
 * @author westy
 */
public class AclTable {
  
  public static String Version = "$Revision:$";

  public AclTable() {
    MySQLUtils.maybeCreateTable(TableName, TableCreate);
  }

  // make it a singleton class
  public static AclTable getInstance() {
    return AclTableHolder.INSTANCE;
  }

  private static class AclTableHolder {

    private static final AclTable INSTANCE = new AclTable();
  }
  public static final String PUBLICKEY = "publickey";
  public static final String GUID = "guid";
  public static final String USERNAME = "username";
  public static final String JSON = "jsonobject";
  private static final String TableName = "acl";
  private static final String TableCreate = "(id INT UNSIGNED NOT NULL AUTO_INCREMENT, PRIMARY KEY (id), " + USERNAME + " TEXT, " + GUID + " CHAR(40), " + PUBLICKEY + " TEXT, " + JSON + " TEXT)";
  private static final String TableStandardQuery = "SELECT id, " + USERNAME + ", " + PUBLICKEY + ", " + GUID + ", " + JSON + " FROM " + TableName;

  private String userUpdate(UserInfo userInfo) {
    return "SET " + USERNAME + " = '" + userInfo.getUserName() + "', " + PUBLICKEY + " = '" + userInfo.getPublicKey() + "', " + GUID + " ='" + userInfo.getGuid() + "'";
  }

  private String valueUpdate(UserInfo userInfo, JSONObject jsonObject) {
    return "SET " + USERNAME + " = '" + userInfo.getUserName() + "', " + PUBLICKEY + " = '" + userInfo.getPublicKey() + "', " + GUID + " ='" + userInfo.getGuid() + "', " + JSON + " ='" + jsonObject.toString() + "'";
  }

  private AclTableEntry lookupFromUserInfo(UserInfo userInfo) {
    return lookupFromGuid(userInfo.getGuid());
  }

  public AclTableEntry lookupFromGuid(String guid) {
    AclTableEntry result = null;
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery + " WHERE " + GUID + " = '" + guid + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);

      ResultSet rs = s.getResultSet();
      if (rs.next()) {
        result = AclTableEntry.createFromResultSet(rs);
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    return result;
  }

  public AclTableEntry lookupFromUserName(String username) {
    AclTableEntry result = null;
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery + " WHERE " + USERNAME + " = '" + username + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);

      ResultSet rs = s.getResultSet();
      if (rs.next()) {
        result = AclTableEntry.createFromResultSet(rs);
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    return result;
  }

  public void addUser(UserInfo userInfo) {
    JSONObject jsonObject;
    AclTableEntry entry = lookupFromUserInfo(userInfo);
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String setPart = userUpdate(userInfo);
      String updateText = null;
      if (entry == null) {
        updateText = "INSERT INTO " + TableName + " " + setPart;
      } else {
        updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + GUID + " = '" + userInfo.getGuid() + "'";
      }
      GCRS.getLogger().finer("Update text:" + updateText);

      s.executeUpdate(updateText);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  public void deleteUser(UserInfo userInfo) {
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = "DELETE FROM " + TableName + " WHERE " + GUID + " = '" + userInfo.getGuid() + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeUpdate(statement);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  public UserInfo findUser(String userName) {
    AclTableEntry entry = lookupFromUserName(userName);
    if (entry != null) {
      return entry.getUserInfo();
    } else {
      return null;
    }
  }

  public Set<String> lookup(UserInfo userInfo, String key) {
    AclTableEntry entry = lookupFromUserInfo(userInfo);
    if (entry != null) {
      JSONObject jsonObject = entry.getJsonObject();
      JSONArray acl = (JSONArray) jsonObject.get(key);
      if (acl != null) {
        return new HashSet(acl);
      }
    }
    return new HashSet<String>();
  }

  public JSONObject lookup(UserInfo userInfo) {
    AclTableEntry entry = lookupFromUserInfo(userInfo);
    if (entry != null) {
      return entry.getJsonObject();
    }
    return new JSONObject();
  }

  public void add(UserInfo userInfo, String key, String value) {
    JSONObject jsonObject;
    AclTableEntry entry = lookupFromUserInfo(userInfo);
    if (entry == null) {
      jsonObject = new JSONObject();
      JSONArray acl = new JSONArray();
      acl.add(value);
      jsonObject.put(key, acl);
    } else {
      jsonObject = entry.getJsonObject();
      JSONArray acl = (JSONArray) jsonObject.get(key);
      if (acl == null) {
        acl = new JSONArray();
      }
      if (!acl.contains(value)) {
        acl.add(value);
      }
      jsonObject.put(key, acl);
    }
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String setPart = valueUpdate(userInfo, jsonObject);
      String updateText = null;
      if (entry == null) {
        updateText = "INSERT INTO " + TableName + " " + setPart;
      } else {
        updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + GUID + " = '" + userInfo.getGuid() + "'";
      }
      GCRS.getLogger().finer("Update text:" + updateText);

      s.executeUpdate(updateText);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  public void remove(UserInfo userInfo, String key, String value) {
    AclTableEntry entry = lookupFromUserInfo(userInfo);
    if (entry != null) {
      JSONObject jsonObject = entry.getJsonObject();
      JSONArray acl = (JSONArray) jsonObject.get(key);
      if (acl != null) {
        if (acl.contains(value)) {
          acl.remove(value);
          jsonObject.put(key, acl);
          try {
            Connection conn = Connect.getConnection();
            Statement s = conn.createStatement();
            String setPart = valueUpdate(userInfo, jsonObject);
            String updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + GUID + " = '" + userInfo.getGuid() + "'";
            GCRS.getLogger().finer("Update text:" + updateText);
            s.executeUpdate(updateText);
          } catch (SQLException e) {
            GCRS.getLogger().severe("Error... problem executing statement : " + e);
          }
        }
      }
    }
  }
  
  public String dump() {
    StringBuilder result = new StringBuilder();
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery;
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);
      ResultSet rs = s.getResultSet();
      while (rs.next()) {
        AclTableEntry entry = AclTableEntry.createFromResultSet(rs);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("username", entry.getUserInfo().getUserName());
        jsonObject.put("guid", entry.getUserInfo().getGuid());
        jsonObject.put("publickey", entry.getUserInfo().getPublicKey());
        jsonObject.put("acl", entry.getJsonObject());
        result.append(jsonObject.toString());
        result.append("\n");
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    if (result.length() > 0) { // trim newline
      result.setLength(result.length() - 1);
    }
    return result.toString().trim();
  }

  public ArrayList<AclTableEntry> retrieveAllEntries() {
    ArrayList<AclTableEntry> result = new ArrayList<AclTableEntry>();
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      ResultSet rs;
      int count;

      s.executeQuery(TableStandardQuery);
      rs = s.getResultSet();
      count = 0;
      while (rs.next()) {
        ++count;
        AclTableEntry entry = AclTableEntry.createFromResultSet(rs);
        GCRS.getLogger().finer(entry.toString());
        result.add(entry);
      }
      GCRS.getLogger().finer(count + " entries were retrieved");
      rs.close();
      s.close();

    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    } finally {
      Connect.closeConnection();
    }
    return result;
  }

  public void printAllEntries() {
    for (AclTableEntry entry : retrieveAllEntries()) {
      System.out.println(entry.toString());
    }
  }

  public void resetTable() {
    MySQLUtils.dropTable(TableName);
    MySQLUtils.maybeCreateTable(TableName, TableCreate);
  }
}
