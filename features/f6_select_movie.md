# Feature 6: End Voting Session and Select Movie

This document provides a detailed description of the "Select Movies” feature which consists of two sub-features: 

- Sub-feature 6.1: End the Voting Session  
- Sub-feature 6.2: Handle Notification for Selected Movie

We describe each sub-feature using the following format:

- A description  
- Primary actor(s)  
- Trigger(s)  
- Success scenario(s)  
- Failure scenario(s)

A description is a short summary of the sub-feature. Primary actors(s) are the users or systems that interact with the sub-feature. Trigger(s) are specific events that initiate the sub-feature. A success scenario is a numbered sequence of steps in the normal flow of events in the system. A failure scenario describes what can go wrong in each step of the success scenario and how this is handled. A failure scenario has the same number as its corresponding success scenario.  For example, if a failure scenario corresponds to step 3, it will be numbered 3a; the next failure scenario corresponding to step 3 will be numbered 3b, etc.

## Sub-feature 6.1: End the Voting Session 

### Description

User (group owner) can end the voting session for a group they own. This action triggers the system to analyze votes from the voting session and determine the selected movie. When a movie is selected, all group members receive a push notification. 

### Primary Actor

- User (group owner)  
- Push Notification Service (Firebase Cloud Messaging)

### Triggers

- User taps the “End Voting Session” button on the Group Details screen.

### Success Scenario

1. The system presents a confirmation message showing the selected movie.  
2. The system uses the Push Notification Service to send a notification to all group members that the selected movie result is out. The message format is: “Group {GroupName}’s selected movie is out!”.  
3. The system calls the [sub-feature 2.3: ‘View Details of a Group’](f2_manage_groups.md#Sub-feature-2.3-View-Details-of-a-Group), displaying the Group Details screen. 

### Failure Scenarios

1a. The system fails to end the voting session. 

- 1a1. The system displays an error message “Failed to end the voting session. Please try again.”   
- 1a2. The system continues to present the Group Details  screen.

2a. Push Notification Service is unavailable or fails to send notifications. 

- 2a1. The system displays a warning message “You ended the voting session successfully but members could not be notified. You might want to contact them directly.”   
- 2a2. The system continues to execute step 3 of the success scenario.

## Sub-feature 6.2: Handle Notification for Selected Movie 

### Description

A group member taps a push notification indicating the group that they joined has the voting session ended and is then redirected to the app to view the selected movie for the group. 

### Primary Actors

- User (group member)

### Triggers

- User (group member) taps a push notification indicating the selected movie result is out. 

### Success Scenario

1. The system opens the app and calls the [sub-feature 2.3: ‘View Details of a Group’](f2_manage_groups.md#Sub-feature-2.3-View-Details-of-a-Group), displaying the Group Details screen. 

### Failure Scenarios

1a. The system fails to launch the MovieSwipe application. 

- 1a1. User is informed that the app could not be opened. 