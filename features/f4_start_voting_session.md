# Feature 4: Start Voting Session 

This document provides a detailed description of the "Manage Voting Session” feature which consists of two sub-features: 

- Sub-feature 4.1: Start Voting Session  
- Sub-feature 4.2: Handle Notification for Voting Session Start

We describe each sub-feature using the following format:

- A description  
- Primary actor(s)  
- Trigger(s)  
- Success scenario(s)  
- Failure scenario(s)

A description is a short summary of the sub-feature. Primary actors(s) are the users or systems that interact with the sub-feature. Trigger(s) are specific events that initiate the sub-feature. A success scenario is a numbered sequence of steps in the normal flow of events in the system. A failure scenario describes what can go wrong in each step of the success scenario and how this is handled. A failure scenario has the same number as its corresponding success scenario.  For example, if a failure scenario corresponds to step 3, it will be numbered 3a; the next failure scenario corresponding to step 3 will be numbered 3b, etc.

## Sub-feature 4.1: Start Voting Session 

### Description

User (the group owner) can start a voting session for the groups they own. This action triggers the system to fetch movies from External Movie Service and generate a list of 10 recommended movies to vote on, based on all members’ genre preferences. When the list of movies is ready, all group members receive a push notification about the voting session has started. 

### Primary Actors

- User (group owner)  
- External Movie Service (TMDB API)  
- Push Notification Service (Firebase Cloud Messaging)

### Triggers 

- User (group owner) taps the "Start Voting Session" button on the Group Details screen.

### Success Scenario

1. The system sends a request to the External Movie Service, to fetch a list of movies that match the genre preferences of all group members.  
2. The External Movie Service returns a list of movies to the system.  
3. The system selects 10 movies prioritized by common genre preferences, while also considering the individual preferences of each group member.  
4. The system uses the Push Notification Service to send a notification to all group members that the group voting session has started. The message format is: “Group {GroupName}’s voting session has started”.  
5. The system calls the [sub-feature 2.3: ‘View Details of a Group’](f2_manage_groups.md#Sub-feature-2.3-View-Details-of-a-Group), displaying the Group Details screen. 

### Failure Scenarios

2a. External Movie Service fails to return a list of movies. 

- 2a1. The system displays an error message "Failed to load movies. Please try again."  
- 2a2. The system continues to present the Group Details screen.

   
4a. Push Notification Service is unavailable or fails to send notifications. 

- 4a1. The system displays a warning message “You started the voting session successfully but members could not be notified. You might want to contact them directly.”  
- 4a2. The system continues to execute step 5 of the success scenario.    

## Sub-feature 4.2: Handle Notification for Voting Session Start

### Description

A group member taps a push notification indicating the group that they joined has the voting session started and is then redirected to the app to join the voting session.  

### Primary Actors

- User (group member)

### Triggers

- User (group member) taps a push notification indicating the group voting session has started. 

### Success Scenario

1. The system opens the app and calls the [sub-feature 2.3: ‘View Details of a Group’](f2_manage_groups.md#Sub-feature-2.3-View-Details-of-a-Group), displaying the Group Details screen. 

### Failure Scenarios

1a. The system fails to launch the MovieSwipe application. 

- 1a1. User is informed that the app could not be opened. 

      