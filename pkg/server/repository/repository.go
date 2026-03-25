package repository

import "database/sql"

type Repositories struct {
	Organizations *OrganizationRepository
	Endpoints     *EndpointRepository
	Scans         *ScanRepository
}

func NewRepositories(db *sql.DB) *Repositories {
	return &Repositories{
		Organizations: NewOrganizationRepository(db),
		Endpoints:     NewEndpointRepository(db),
		Scans:         NewScanRepository(db),
	}
}
