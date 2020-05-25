package main

import "time"

// audit logs events to the audit table
func (app *App) audit(user, event, info string) error {
	return app.db.SaveAudit(time.Now(), user, event, info)
}
