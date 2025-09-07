# Feature 1: Manage Authentication

This document provides a detailed description of the "Manage Authentication” feature which consists of two sub-features:

- Sub-feature 1.1: Sign In  
- Sub-feature 1.2: Sign Out

   
We describe each sub-feature using the following format:

- A description  
- Primary actor(s)  
- Trigger(s)  
- Success scenario(s)  
- Failure scenario(s)

A description is a short summary of the sub-feature. Primary actors(s) are the users or systems that interact with the sub-feature. Trigger(s) are specific events that initiate the sub-feature. A success scenario is a numbered sequence of steps in the normal flow of events in the system. A failure scenario describes what can go wrong in each step of the success scenario and how this is handled. A failure scenario has the same number as its corresponding success scenario.  For example, if a failure scenario corresponds to step 3, it will be numbered 3a; the next failure scenario corresponding to step 3 will be numbered 3b, etc.

## Sub-feature 1.1: Sign In

### Description

To access app features, a user must authenticate using External Authentication Service first. New users are automatically registered with the app upon the first authentication.

### Primary Actors

- User  
- External Authentication Service (Google Authentication Service)

### Triggers

- User that has not yet signed in or whose authentication token has expired launches the MovieSwipe application.

### Success Scenario

1. The system displays the Authentication screen with the "Sign in with Google" button.  
2. User taps the "Sign in with Google" button.  
3. The system initiates Google authentication flow, prompting the user to provide their Google credentials.  
4. User completes the Google authentication process.  
5. Google Authentication Service authenticates the user.  
6. The system calls the [sub-feature 2.2: ‘View Groups List’](./f2_manage_groups.md#Sub-feature-2.2-View-Groups-List), displaying the Group List screen.

### Failure Scenario

3a. Google Authentication Service is unavailable. 

- 3a1. The system displays an error message "Authentication service temporarily unavailable. Please try again."   
- 3a2. The system executes step 1 of the success scenario again.

5a. Authentication fails. 

- 5a1. The system displays an error message "Authentication unsuccessful. Please try again."  
- 5a2. The system executes step 3 of the success scenario again.

## Sub-feature 1.2: Sign Out 

### Description

An authenticated user can sign out. 

### Primary Actor

- User  
- External Authentication Service (Google Authentication Service)

### Triggers

- User taps the “Sign out” button on the Group List screen.   
- When opening the app, the system redirects User, whose authentication token has expired, to the Authentication screen.

### Success Scenario

1. The system initiates the sign out process by calling the Google Authentication Service to end the current session.   
2. Google Authentication Service revokes the user’s authentication token and confirms session termination.   
3. The system presents a confirmation message showing successful sign out and closes the app.

### Failure Scenarios

1a. Google Authentication Service is unavailable. 

- 1a1. The system displays an error message "Authentication service temporarily unavailable, cannot sign out. Please try again." and stays on its current screen.