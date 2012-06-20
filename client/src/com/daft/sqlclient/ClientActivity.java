package com.daft.sqlclient;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

public class ClientActivity extends Activity {
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        Button sendButton = (Button)findViewById(R.id.sendButton);
        sendButton.setOnClickListener(sendOnClickListener);
    }
    
    public String[] getFile() throws FileNotFoundException {
    	FileInputStream is = new FileInputStream("/data/test.txt");
    	BufferedReader reader = new BufferedReader(new InputStreamReader(is));
    	
    	String[] RowData = null;
    	try {
    		String line;
    		while ((line = reader.readLine()) != null) {
    			RowData = line.split(",");
                String name = RowData[0];
                String value = RowData[1];
    		}
    	} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try {
	            is.close();
	        }
	        catch (IOException e) {
	            // handle exception
	        }
    	}
		return RowData;
    }
    
    public class SQLUpdate extends AsyncTask<Void,Void,Void> {

    	@Override
    	protected Void doInBackground(Void... params) {
    		try {
				postData(findViewById(R.id.sendButton),getFile());
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
    	}

    	ArrayList<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
    	final EditText nameBox = (EditText) findViewById(R.id.nameBox);
    	final EditText valueBox = (EditText) findViewById(R.id.valueBox);
    	
    	public void postData(View v, String[] Data) {
    		nameValuePairs.add(new BasicNameValuePair("name",Data[0].toString()));
    		nameValuePairs.add(new BasicNameValuePair("value",Data[1].toString()));

    		//HTTP post
    		try {
    			HttpClient httpclient = new DefaultHttpClient();
    			HttpPost httppost = new      
    					HttpPost("http://69.141.103.189/testsql.php");
    			httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
    			HttpResponse response = httpclient.execute(httppost);
    			HttpEntity entity = response.getEntity();
    			InputStream is = entity.getContent();
    			Log.i("postData", response.getStatusLine().toString());
    		} catch (UnsupportedEncodingException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    		} catch (IllegalStateException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    		} catch (IOException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    		}
    	}
    }
    
    Button.OnClickListener sendOnClickListener = new Button.OnClickListener(){
    	public void onClick(View v) {
    		new SQLUpdate().execute();
    	}
    };
}