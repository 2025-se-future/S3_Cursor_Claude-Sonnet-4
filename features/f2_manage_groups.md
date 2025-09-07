# Feature 2: Manage Groups

This document provides a detailed description of the "Manage Groups” feature which consists of five sub-features: 

- Sub-feature 2.1: Create Group  
- Sub-feature 2.2: View Groups List   
- Sub-feature 2.3: View Details of a Group  
- Sub-feature 2.4: Delete Group  
- Sub-feature 2.5: Handle Notification for Group Deletion

We describe each sub-feature using the following format:

- A description  
- Primary actor(s)  
- Trigger(s)  
- Success scenario(s)  
- Failure scenario(s)

A description is a short summary of the sub-feature. Primary actors(s) are the users or systems that interact with the sub-feature. Trigger(s) are specific events that initiate the sub-feature. A success scenario is a numbered sequence of steps in the normal flow of events in the system. A failure scenario describes what can go wrong in each step of the success scenario and how this is handled. A failure scenario has the same number as its corresponding success scenario.  For example, if a failure scenario corresponds to step 3, it will be numbered 3a; the next failure scenario corresponding to step 3 will be numbered 3b, etc.

## Sub-feature 2.1: Create Group

### Description

A user can create a group and become its owner. When creating a group, the group owner provides the group name and specifies their movie genre preferences. The list of genres is fetched from the External Movie Service. 

### Primary Actors

- User  
- External Movie Service (TMDB API)

### Triggers

- User taps the “Create New Group” button on the Group List  screen.

### Success Scenario

1. The system displays a dialog to enter the “Group Name”, with an “Next” button.  
2. User enters a group name and taps the “Next” button.  
3. The system displays the Genre Preferences screen with checkboxes for available genres, which are fetched from the External Movie Service.  
4. User selects checkboxes for each of their preferred movie genres.  
5. User taps the “Create Group” button to create the group and become the group owner.  
6. The system creates the new group and stores its details and the selected genres.   
7. The system calls the [sub-feature 2.3: ‘View Details of a Group’](f2_manage_groups.md#Sub-feature-2.3-View-Details-of-a-Group), displaying the Group Details screen. 

### Failure Scenarios

2a. User enters an empty or invalid group name. 

- 2a1. The system displays an error message “Group name is required and must be 3-30 alphanumeric characters.”  
- 2a2. The system continues to present the dialog to enter the group name, which shows the information entered by the user. 

   
3a. The system fails to load the list of genres. 

- 3a1. The system displays an error message “Failed to load movie genres. Please try again.”   
- 3a2. User taps the “Try Again” button.   
- 3a3. The system executes step 3 of the success scenario again. 

5a. User selects no genres. 

- 5a1. The system displays an error message “Genre selection is required. Please choose at least one preferred movie genre.”   
- 5a2. The system continues to present the Genre Preferences screen. 

6a. The system fails to create the group. 

- 6a1. The system displays an error message “Failed to create group. Please try again.”   
- 6a2. User taps the “Try Again” button.  
- 6a3. The system executes step 6 of the success scenario again.

## Sub-feature 2.2: View Groups List

### Description

A user can view a list of groups they created or joined.

### Primary Actor

- User

### Triggers

- The system redirects User to the Group List screen, either from another screen or when opening the app with the authentication token that has not expired. 

### Success Scenario

1. The system displays the Group List screen, with a list of groups the user has created or joined. Each group item in the list includes the group name and the user’s role: either “owner” or “member”. The screen also contains two buttons: “Create New Group” and “Join Group”.

### Failure Scenarios

1a. The system fails to load the list of groups that the user has created or joined.

- 1a1. The system displays an alert dialog with an error message “Failed to load groups. Please retry.” The dialog has a “Retry” button.  
- 1a2. User taps the “Retry” button.  
- 1a3. The system executes step 1 of the success scenario again, to re-load the groups list.

## Sub-feature 2.3: View Details of a Group

### Description

A user can view detailed information of a group where they are the owner or a member. The screen displays different content and actions based on the user's role, the group’s voting session state, and the user's individual voting progress.

### Primary Actor

- User

### Triggers

- User selects a group from the Group List screen, to view the group's detailed information.  
- The system redirects User to the Group Details screen from another app screen.  
- User taps on a notification about the group 

### Success Scenario

1. The system displays the Group Details screen containing two sections: group information and voting information.  
   * Group information section content depends on the user’s role:  
     * If User is the owner of the group: Shows the group name, user’s role (i.e., “owner”), a unique invitation code for member recruitment, list of members in the group, and a “Delete Group” button.  
     * If User is a member of the group: Shows the group name, user’s role (i.e., “member”), and a “Leave Group” button.  
   * Voting information section content depends on the user’s role, the group’s voting session state, and the user’s individual voting progress:  
     * If User is the owner of the group:  
       * If the voting session has not started: Shows a “Start Voting Session” button.  
       * If the voting session has started but not yet ended:  
         1. If User has not voted: Shows a “Join Voting Session” button and an “End Voting Session” button.  
         2. If User has voted for a subset of movies: Shows a “Resume Voting Session” button and an “End Voting Session” button.  
         3. If User has voted for all movies: Shows an “End Voting Session” button.   
       * If the voting session ended: Shows the selected movie (title, poster, genre, rating, length, and summary).   
     * If User is a member of the group:   
       * If the voting session has not started: Shows the text “Waiting for the owner to start the session”.  
       * If the voting session started but not yet ended:  
         1. If User has not voted: Shows a “Join Voting Session” button.  
         2. If User has voted for a subset of movies: Shows a “Resume Voting Session” Button.  
         3. If User has voted for all movies: Shows the text “Waiting for the owner to end the session”.  
       * If the voting session has ended: Shows the selected movie (title, poster, genre, rating, length, and summary).   

### Failure Scenario

1a. The group has been deleted by the owner.

- 1a1. The system displays an error message “This group has been deleted.”  
- 1a2. The system calls the [sub-feature 2.2: ‘View Groups List’](./f2_manage_groups.md#Sub-feature-2.2-View-Groups-List), displaying the updated Group List screen.

1b. User is no longer a member of the group. 

- 1b1. The system displays an error message “You are no longer a member of this group.”  
- 1b2. The system calls the [sub-feature 2.2: ‘View Groups List’](./f2_manage_groups.md#Sub-feature-2.2-View-Groups-List), displaying the Group List screen with the list of groups for which the user is a member or an owner.

1c. The system fails to load the group and voting information. 

- 1c1. The system displays an error message “Failed to load group information.” and stays on its current screen.

## Sub-feature 2.4: Delete Group

### Description 

A user can delete groups they own. When a group is deleted, all group members receive a push notification. 

### Primary Actor

- User (group owner)  
- Push Notification Service (Firebase Cloud Messaging)

### Triggers

- User (group owner) taps the “Delete Group” button on the Group Details screen. 

### Success Scenario

1. The system displays a confirmation dialog, asking the user to confirm their decision to permanently delete the group.   
2. User confirms deleting the group by tapping the “Delete” button on the confirmation dialog.   
3. The system deletes the group and its associated details. It presents a confirmation message for deleting the group successfully .  
4. The system uses the Push Notification Service to send a notification to all group members that the group has been deleted. The message format is: “Group {GroupName} has been deleted by the owner.”  
5. The system calls the [sub-feature 2.2: ‘View Groups List’](./f2_manage_groups.md#Sub-feature-2.2-View-Groups-List), displaying the Group List screen.

### Failure Scenarios

3a. The system fails to delete the group. 

- 3a1. The system displays an error message “Failed to delete group. Please try again.”   
- 3a2. The system stays on the current screen, displaying the Group Details.

4a. Push Notification Service is unavailable or fails to send notifications. 

- 4a1. The system displays a warning message “You deleted the group successfully but members could not be notified. You might want to contact them directly.”   
- 4a2. The system continues to step 5 of the success scenario. 

## Sub-feature 2.5: Handle Notification for Group Deletion

### Description 

A group member taps a push notification indicating the group that they joined has been deleted by the owner and is then redirected to the app to view the updated list of groups that they created or joined. 

### Primary Actor

- User (group member)

### Triggers

- User (group member) taps a push notification indicating that the group has been deleted by the owner. 

### Success Scenario

1. The system opens the app and calls the [sub-feature 2.2: ‘View Groups List’](./f2_manage_groups.md#Sub-feature-2.2-View-Groups-List), displaying the Group List screen with the updated group list. 

### Failure Scenarios

1a. The system fails to launch the MovieSwipe application. 

- 1a1. User is informed that the app could not be opened. 