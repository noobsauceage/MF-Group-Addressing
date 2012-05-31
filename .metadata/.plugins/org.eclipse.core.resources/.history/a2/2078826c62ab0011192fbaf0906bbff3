package com.daft.sqlclient;

import java.io.IOException;
import java.io.InputStream;
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

public class ClientActivity extends Activity {
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        Button testButton = (Button)findViewById(R.id.button1);
        testButton.setOnClickListener(testOnClickListener);
    }
    
    public class SQLUpdate extends AsyncTask<Void,Void,Void> {

    	@Override
    	protected Void doInBackground(Void... params) {
    		postData(findViewById(R.id.button1));
			return null;
    	}

    	ArrayList<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();

    	public void postData(View v) {
    		nameValuePairs.add(new BasicNameValuePair("name","J"));
    		nameValuePairs.add(new BasicNameValuePair("value","2"));

    		//HTTP post
    		try {
    			HttpClient httpclient = new DefaultHttpClient();
    			HttpPost httppost = new      
    					HttpPost("http://192.168.207.68/testsql.php");
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
    
    Button.OnClickListener testOnClickListener = new Button.OnClickListener(){
    	public void onClick(View v) {
    		new SQLUpdate().execute();
    	}
    };
}