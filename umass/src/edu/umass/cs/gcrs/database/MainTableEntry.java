/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.database;

import edu.umass.cs.gcrs.gcrs.GCRS;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

/**
 *
 * @author westy
 */
public class MainTableEntry {

  private String guid;
  private JSONObject jsonObject;

  public String getGuid() {
    return guid;
  }

  public JSONObject getJsonObject() {
    return jsonObject;
  }

  static MainTableEntry createFromResultSet(ResultSet rs) {
    MainTableEntry result = new MainTableEntry();
    try {
      int idVal = rs.getInt("id");
      result.guid = rs.getString(MainTable.GUID);
      result.jsonObject = (JSONObject) JSONValue.parse(rs.getString(MainTable.JSON));
      GCRS.getLogger().finer("id = " + idVal + ", guid = " + result.guid + ", json = " + result.jsonObject);
      return result;
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
      return null;
    }
  }

  @Override
  public String toString() {
    return "MainTableEntry{" + "guid=" + guid + ", jsonObject=" + jsonObject + '}';
  }
}
