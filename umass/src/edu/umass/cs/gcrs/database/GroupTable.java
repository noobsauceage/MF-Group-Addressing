package edu.umass.cs.gcrs.database;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.GroupInfo;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
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
public class GroupTable {
  
  public static String Version = "$Revision$";

  public GroupTable() {
    MySQLUtils.maybeCreateTable(TableName, TableCreate);
  }
  
  // make it a singleton class
  public static GroupTable getInstance() {
    return GroupTableHolder.INSTANCE;
  }

  private static class GroupTableHolder {

    private static final GroupTable INSTANCE = new GroupTable();
  }
  
  public static final String PUBLICKEY = "publickey";
  public static final String GUID = "guid";
  public static final String GROUPNAME = "groupname";
  public static final String JSON = "jsonobject";
  private static final String TableName = "grouptable"; // cuz group is reserved in mysql
  private static final String TableCreate = "(id INT UNSIGNED NOT NULL AUTO_INCREMENT, PRIMARY KEY (id), " + GROUPNAME + " TEXT, " + GUID + " CHAR(40), " + PUBLICKEY + " TEXT, " + JSON + " TEXT)";
  private static final String TableStandardQuery = "SELECT id, " + GROUPNAME + ", " + PUBLICKEY + ", " + GUID + ", " + JSON + " FROM " + TableName;

  private String userUpdate(GroupInfo groupInfo) {
    return "SET " + GROUPNAME + " = '" + groupInfo.getGroupName() + "', " + PUBLICKEY + " = '" + groupInfo.getPublicKey() + "', " + GUID + " ='" + groupInfo.getGuid() + "'";
  }

  private String valueUpdate(GroupInfo groupInfo, JSONArray array) {
    return "SET " + GROUPNAME + " = '" + groupInfo.getGroupName() + "', " + PUBLICKEY + " = '" + groupInfo.getPublicKey() + "', " + GUID + " ='" + groupInfo.getGuid() + "', " + JSON + " ='" + array.toString() + "'";
  }

  private GroupTableEntry lookupFromGroupInfo(GroupInfo groupInfo) {
    return lookupFromGuid(groupInfo.getGuid());
  }
  
  public GroupTableEntry lookupFromGuid(String guid) {
    GroupTableEntry result = null;
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery + " WHERE " + GUID + " = '" + guid + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);

      ResultSet rs = s.getResultSet();
      if (rs.next()) {
        result = GroupTableEntry.createFromResultSet(rs);
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    return result;
  }
  
  public GroupTableEntry lookupFromGroupName(String groupname) {
    GroupTableEntry result = null;
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery + " WHERE " + GROUPNAME + " = '" + groupname + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);

      ResultSet rs = s.getResultSet();
      if (rs.next()) {
        result = GroupTableEntry.createFromResultSet(rs);
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    return result;
  }
  
  public void addGroup(GroupInfo groupinfo) {
    JSONObject jsonObject;
    GroupTableEntry entry = lookupFromGroupInfo(groupinfo);
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String setPart = userUpdate(groupinfo);
      String updateText = null;
      if (entry == null) {
        updateText = "INSERT INTO " + TableName + " " + setPart;
      } else {
        updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + GUID + " = '" + groupinfo.getGuid() + "'";
      }
      GCRS.getLogger().finer("Update text:" + updateText);

      s.executeUpdate(updateText);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  public void deleteGroup(GroupInfo groupinfo) {
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = "DELETE FROM " + TableName + " WHERE " + GUID + " = '" + groupinfo.getGuid() + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeUpdate(statement);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }
  
   public GroupInfo findGroup(String groupname) {
    GroupTableEntry entry = lookupFromGroupName(groupname);
    if (entry != null) {
      return entry.getGroupInfo();
    } else {
      return null;
    }
  }

  public JSONArray lookup(GroupInfo groupinfo) {
    GroupTableEntry entry = lookupFromGroupInfo(groupinfo);
    if (entry != null) {
      return entry.getJsonArray();
    }
    return new JSONArray();
  }

  public void add(GroupInfo groupinfo, String memberGuid) {
    JSONArray members;
    GroupTableEntry entry = lookupFromGroupInfo(groupinfo);
    if (entry == null) {
      members = new JSONArray();
      members.add(memberGuid);
    } else {
      members = entry.getJsonArray();
      if (members == null) {
        members = new JSONArray();
      }
      if (!members.contains(memberGuid)) {
        members.add(memberGuid);
      }
    }
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String setPart = valueUpdate(groupinfo, members);
      String updateText = null;
      if (entry == null) {
        updateText = "INSERT INTO " + TableName + " " + setPart;
      } else {
        updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + GUID + " = '" + groupinfo.getGuid() + "'";
      }
      GCRS.getLogger().finer("Update text:" + updateText);

      s.executeUpdate(updateText);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  public void remove(GroupInfo groupinfo, String memberGuid) {
     GroupTableEntry entry = lookupFromGroupInfo(groupinfo);
    if (entry != null) {
      JSONArray members = entry.getJsonArray();
      if (members != null) {
        if (members.contains(memberGuid)) {
          members.remove(memberGuid);
          try {
            Connection conn = Connect.getConnection();
            Statement s = conn.createStatement();
            String setPart = valueUpdate(groupinfo, members);
            String updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + GUID + " = '" + groupinfo.getGuid() + "'";
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
        GroupTableEntry entry = GroupTableEntry.createFromResultSet(rs);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("groupname", entry.getGroupInfo().getGroupName());
        jsonObject.put("guid", entry.getGroupInfo().getGuid());
        jsonObject.put("publickey", entry.getGroupInfo().getPublicKey());
        jsonObject.put("members", entry.getJsonArray());
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

  public ArrayList<GroupTableEntry> retrieveAllEntries() {
    ArrayList<GroupTableEntry> result = new ArrayList<GroupTableEntry>();
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
        GroupTableEntry entry = GroupTableEntry.createFromResultSet(rs);
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
    for (GroupTableEntry entry : retrieveAllEntries()) {
      System.out.println(entry.toString());
    }
  }

  public void resetTable() {
    MySQLUtils.dropTable(TableName);
    MySQLUtils.maybeCreateTable(TableName, TableCreate);
  }
}
