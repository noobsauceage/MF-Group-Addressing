/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.gcrs;

import edu.umass.cs.gcrs.utilities.Utils;

/**
 *
 * @author westy
 */
public abstract class BasicHashFunction implements HashFunction {
  
  @Override
  public long hashToLong(String key) {
    // assumes the first byte is the most significant
    return Utils.byteArrayToLong(hash(key));
  }
  
}
