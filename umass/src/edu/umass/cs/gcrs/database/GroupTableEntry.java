/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.database;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.GroupInfo;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.json.simple.JSONArray;
import org.json.simple.JSONValue;

/**
 * Holds the contents of an entry in the access control table. The
 * jsonobject contains the key and value pairs that determine user access. Each
 * key is the name of field and the value is a list of users that can access that field.
 *
 * @author westy
 */
public class GroupTableEntry {

  private GroupInfo groupInfo;
  private JSONArray array = null;

  public GroupInfo getGroupInfo() {
    return groupInfo;
  }

  public JSONArray getJsonArray() {
    if (array == null) { // if there isn't one in the DB gin one up
      return new JSONArray();
    } else {
      return array;
    }
  }

  static GroupTableEntry createFromResultSet(ResultSet rs) {
    GroupTableEntry result = new GroupTableEntry();
    try {
      int idVal = rs.getInt("id");
      result.groupInfo = new GroupInfo(rs.getString(GroupTable.GROUPNAME), rs.getString(GroupTable.GUID), rs.getString(GroupTable.PUBLICKEY));
      if (rs.getString(MainTable.JSON) != null) {
        result.array = (JSONArray) JSONValue.parse(rs.getString(GroupTable.JSON));
      }
      GCRS.getLogger().finer("id = " + idVal + ", guid = " + result.groupInfo.getGuid() + ", json = " + result.array);
      return result;
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
      return null;
    }
  }

  @Override
  public String toString() {
    return "GroupTableEntry{" + "groupInfo=" + groupInfo + ", jsonArray=" + array + '}';
  }

}
