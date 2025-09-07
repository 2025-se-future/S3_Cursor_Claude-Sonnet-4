package com.movieswipe.ui.navigation

sealed class Screen(val route: String) {
    object Login : Screen("login")
    object GroupList : Screen("group_list")
    object GroupDetails : Screen("group_details/{groupId}") {
        fun createRoute(groupId: String) = "group_details/$groupId"
    }
    object CreateGroup : Screen("create_group")
    object JoinGroup : Screen("join_group")
    object Profile : Screen("profile")
    object VotingSession : Screen("voting_session/{sessionId}") {
        fun createRoute(sessionId: String) = "voting_session/$sessionId"
    }
    object VotingResult : Screen("voting_result/{sessionId}") {
        fun createRoute(sessionId: String) = "voting_result/$sessionId"
    }
    object MovieDetails : Screen("movie_details/{movieId}") {
        fun createRoute(movieId: String) = "movie_details/$movieId"
    }
    object GenreSelection : Screen("genre_selection")
}
