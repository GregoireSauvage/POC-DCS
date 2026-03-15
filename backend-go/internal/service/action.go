package service

type Action string

const (
	ActionBootstrap       Action = "bootstrap"
	ActionAuditRead       Action = "audit.read"
	ActionPerfRead        Action = "perf.read"
	ActionFilmRead        Action = "film.read"
	ActionFilmCreate      Action = "film.create"
	ActionFilmUpdateTime  Action = "film.update_time"
	ActionHallRead        Action = "hall.read"
	ActionHallCreate      Action = "hall.create"
	ActionSpectatorRead   Action = "spectator.read"
	ActionSpectatorCreate Action = "spectator.create"
	ActionSearchSpectator Action = "search.spectator"
)
