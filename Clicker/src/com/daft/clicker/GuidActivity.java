package com.daft.clicker;

import java.io.IOException;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

public class GuidActivity extends Activity {
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.guidlayout);

		Button guidButton = (Button) findViewById(R.id.button1);
		guidButton.setOnClickListener(guidOnClickListener);

	}

	final EditText nameText = (EditText) findViewById(R.id.nameText);
	final EditText keyText = (EditText) findViewById(R.id.keyText);

	final TextView guidText = (TextView) findViewById(R.id.guidText);

	Button.OnClickListener guidOnClickListener = new Button.OnClickListener() {
		public void onClick(View v) {
			try {
				guidText.setText(getGuid(nameText.getText().toString(), keyText
						.getText().toString()));
			} catch (ClientProtocolException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	};

	public String getGuid(String name, String key)
			throws ClientProtocolException, IOException {
		HttpClient httpclient = new DefaultHttpClient();
		HttpGet httpget = new HttpGet(
				"http://umassmobilityfirst.net/GCRS/registerEntity?name="
						+ name + "&publickey=" + key);
		HttpResponse response = httpclient.execute(httpget);
		HttpEntity entity = response.getEntity();

		return entity.toString();
	}
}
