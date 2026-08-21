SESSION_TIMEOUT_MINUTES = 30

def check_session_expired(last_active_time, current_time):
    elapsed = current_time - last_active_time
    return elapsed > SESSION_TIMEOUT_MINUTES * 60