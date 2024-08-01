# To-Do App

## Description

A simple to-do application built with Flask that allows users to manage tasks and includes user authentication for secure access.


Made use of sessions instead of cookies for user recognition
Configure session to use filesystem (instead of signed cookies)

Use css for front-end styling

## Features

- User registration and login
- Task creation, editing, and deletion
- Responsive design

## Ignores

Ignored the instance directory cause it is created automatically during each run with the database if the database does not exist already

The flask_session because it also is created during each run if not existing