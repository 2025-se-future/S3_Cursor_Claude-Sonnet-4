package com.movieswipe.ui.screens.groups

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExitToApp
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.movieswipe.ui.components.LoadingSpinner
import com.movieswipe.ui.viewmodels.users.AuthViewModel
import com.movieswipe.utils.UiState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupListScreen(
    onSignOut: () -> Unit,
    authViewModel: AuthViewModel = hiltViewModel()
) {
    val userState by authViewModel.userState
    val signOutState by authViewModel.signOutState
    
    // Handle sign out state
    LaunchedEffect(signOutState) {
        when (signOutState) {
            is UiState.Success -> {
                onSignOut()
                authViewModel.resetSignOutState()
            }
            else -> {}
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "My Groups",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    // User profile icon
                    IconButton(onClick = { /* Navigate to profile */ }) {
                        Icon(
                            imageVector = Icons.Default.Person,
                            contentDescription = "Profile"
                        )
                    }
                    
                    // Sign out button
                    IconButton(
                        onClick = { authViewModel.signOut() }
                    ) {
                        Icon(
                            imageVector = Icons.Default.ExitToApp,
                            contentDescription = "Sign Out"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentAlignment = Alignment.Center
        ) {
            when (val state = userState) {
                is UiState.Loading -> {
                    LoadingSpinner()
                }
                is UiState.Success -> {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "Welcome, ${state.data.name}!",
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold
                        )
                        
                        Text(
                            text = "Email: ${state.data.email}",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        
                        Spacer(modifier = Modifier.height(32.dp))
                        
                        Text(
                            text = "🎬 Groups will be displayed here 🎬",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                        
                        Text(
                            text = "This is Feature 2: Manage Groups (not yet implemented)",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                        )
                    }
                }
                is UiState.Error -> {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "Error loading profile",
                            style = MaterialTheme.typography.headlineSmall,
                            color = MaterialTheme.colorScheme.error
                        )
                        
                        Text(
                            text = state.message,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        
                        Button(
                            onClick = { authViewModel.getCurrentUser() }
                        ) {
                            Text("Retry")
                        }
                    }
                }
                else -> {
                    Text("Loading...")
                }
            }
            
            // Show loading overlay during sign out
            if (signOutState is UiState.Loading) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues),
                    contentAlignment = Alignment.Center
                ) {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.9f)
                        )
                    ) {
                        Column(
                            modifier = Modifier.padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            LoadingSpinner()
                            Text("Signing out...")
                        }
                    }
                }
            }
        }
    }
}
