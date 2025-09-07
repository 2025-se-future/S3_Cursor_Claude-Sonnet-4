package com.movieswipe.ui.navigation

import androidx.compose.runtime.*
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.movieswipe.ui.screens.groups.GroupListScreen
import com.movieswipe.ui.screens.users.LoginScreen
import com.movieswipe.ui.viewmodels.users.AuthViewModel

@Composable
fun AppNavigation(
    navController: NavHostController,
    authViewModel: AuthViewModel = hiltViewModel()
) {
    val isLoggedIn by authViewModel.isLoggedIn
    
    NavHost(
        navController = navController,
        startDestination = if (isLoggedIn) Screen.GroupList.route else Screen.Login.route
    ) {
        composable(Screen.Login.route) {
            LoginScreen(
                onLoginSuccess = {
                    navController.navigate(Screen.GroupList.route) {
                        popUpTo(Screen.Login.route) { inclusive = true }
                    }
                },
                authViewModel = authViewModel
            )
        }
        
        composable(Screen.GroupList.route) {
            GroupListScreen(
                onSignOut = {
                    navController.navigate(Screen.Login.route) {
                        popUpTo(0) { inclusive = true }
                    }
                },
                authViewModel = authViewModel
            )
        }
        
        // Future screens will be added here
        // composable(Screen.CreateGroup.route) { ... }
        // composable(Screen.JoinGroup.route) { ... }
        // etc.
    }
}
