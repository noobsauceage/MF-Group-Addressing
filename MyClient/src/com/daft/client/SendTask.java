package com.daft.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import android.os.AsyncTask;


public class SendTask extends AsyncTask<Void, Void, Void> {

	DataOutputStream dataOutputStream = null;
	DataInputStream dataInputStream = null;
	
	protected Void doInBackground(Void...voids) {
		// TODO Auto-generated method stub

		Socket socket = null;

		try {
			socket = new Socket("192.168.207.68", 8888);
			dataOutputStream = new DataOutputStream(socket.getOutputStream());
			dataInputStream = new DataInputStream(socket.getInputStream());
			dataOutputStream.writeUTF(MyClientActivity.textOut.getText().toString());

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally{
			if (socket != null){
				try {
					socket.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

			if (dataOutputStream != null){
				try {
					dataOutputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

			if (dataInputStream != null){
				try {
					dataInputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return null;
	}
	
	protected Void onPostExecute() {
		try {
			MyClientActivity.textIn.setText(dataInputStream.readUTF());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
