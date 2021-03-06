package com.daft.clicker;

import android.app.ListActivity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;

public class StartActivity extends ListActivity {
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setListAdapter(new ArrayAdapter<String>(this, R.layout.list_item,
				menuItems));

		ListView lv = getListView();
		lv.setTextFilterEnabled(true);

		lv.setOnItemClickListener(new OnItemClickListener() {
			public void onItemClick(AdapterView<?> parent, View view,
					int position, long id) {
				// When clicked, switch to appropriate activity
				switch (position) {
				case 0:
					Intent guidActivity = new Intent(StartActivity.this,
							GuidActivity.class);
					startActivity(guidActivity);
					break;
				case 1:
					Intent notesActivity = new Intent(getApplicationContext(),
							NotesActivity.class);
					startActivity(notesActivity);
					break;
				case 2:
					Intent chatActivity = new Intent(getApplicationContext(),
							ChatActivity.class);
					startActivity(chatActivity);
					break;
				case 3:
					Intent clickerActivity = new Intent(
							getApplicationContext(), ClickerActivity.class);
					startActivity(clickerActivity);
					break;
				}
			}
		});
	}

	static final String[] menuItems = new String[] { "GUID Test", "Clicker",
			"Notes", "Chat" };
}
