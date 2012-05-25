package com.daft.client;

//import java.io.DataInputStream;
//import java.io.DataOutputStream;
//import java.io.IOException;
//import java.net.Socket;
//import java.net.UnknownHostException;

import android.app.Activity;
//import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
//import android.os.Bundle;

public class MyClientActivity extends Activity {

	static EditText textOut;
	static TextView textIn;

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		textOut = (EditText)findViewById(R.id.textout);
		Button buttonSend = (Button)findViewById(R.id.send);
		textIn = (TextView)findViewById(R.id.textin);
		buttonSend.setOnClickListener(buttonSendOnClickListener);
	}

	Button.OnClickListener buttonSendOnClickListener
	= new Button.OnClickListener(){
		
		@Override
		public void onClick(View arg0) {
			new SendTask().execute();
		}
	};
}

