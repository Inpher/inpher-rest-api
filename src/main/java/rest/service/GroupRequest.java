package rest.service;

import java.io.Serializable;
import java.util.List;

public class GroupRequest implements Serializable {
	private String groupName;
	private List<String> usernames;

	public String getGroupName() {
		return groupName;
	}

	public void setGroupName(String groupName) {
		this.groupName = groupName;
	}

	public List<String> getUsernames() {
		return usernames;
	}

	public void setUsernames(List<String> usernames) {
		this.usernames = usernames;
	}

}
