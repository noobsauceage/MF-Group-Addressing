/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.database;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.gcrs.UserInfo;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

/**
 * Holds the contents of an entry in the access control table. The
 * jsonobject contains the key and value pairs that determine user access. Each
 * key is the name of field and the value is a list of users that can access that field.
 *
 * @author westy
 */
public class AclTableEntry {

  private UserInfo userInfo;
  private JSONObject jsonObject = null;

  public UserInfo getUserInfo() {
    return userInfo;
  }

  public JSONObject getJsonObject() {
    if (jsonObject == null) { // if there isn't one in the DB gin one up
      return new JSONObject();
    } else {
      return jsonObject;
    }
  }

  static AclTableEntry createFromResultSet(ResultSet rs) {
    AclTableEntry result = new AclTableEntry();
    try {
      int idVal = rs.getInt("id");
      result.userInfo = new UserInfo(rs.getString(AclTable.USERNAME), rs.getString(AclTable.GUID), rs.getString(AclTable.PUBLICKEY));
      if (rs.getString(MainTable.JSON) != null) {
        result.jsonObject = (JSONObject) JSONValue.parse(rs.getString(AclTable.JSON));
      }
      GCRS.getLogger().finer("id = " + idVal + ", userInfo = " + result.userInfo + ", json = " + result.jsonObject);
      return result;
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
      return null;
    }
  }

  @Override
  public String toString() {
    return "AclTableEntry{" + "userInfo=" + userInfo + ", jsonObject=" + jsonObject + '}';
  }
}
