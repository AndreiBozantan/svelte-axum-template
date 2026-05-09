-- Migration: registrul_init
-- Created at: 2026-05-03 17:31:39

CREATE TABLE IF NOT EXISTS user_profiles (
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verification_domains VARCHAR(200),  -- semicolon-separated values for simplicity
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS legal_entities (
    id INT PRIMARY KEY,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    updated_by INT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'inactive')),
    type VARCHAR(20) NOT NULL CHECK (party_type IN ('person', 'company')),
    county VARCHAR(100),
    city VARCHAR(100),
    street_name VARCHAR(255),
    street_number VARCHAR(10),
    postal_code VARCHAR(10),
    iban VARCHAR(34),
    bank_name VARCHAR(255),
    phone VARCHAR(20),
    email VARCHAR(255),
);
CREATE INDEX IF NOT EXISTS idx_legal_entities_tenant_id ON legal_entities(tenant_id);

CREATE TABLE IF NOT EXISTS companies (
    id INT PRIMARY KEY REFERENCES legal_entities(id),
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    admin_name VARCHAR(255),
    tax_id VARCHAR(50) NOT NULL,
    trade_register_number VARCHAR(50) NOT NULL,
);
CREATE INDEX IF NOT EXISTS idx_companies_tenant_id ON companies(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_name ON companies(tenant_id, name);

CREATE TABLE IF NOT EXISTS persons (
    id PRIMARY KEY REFERENCES legal_entities(id),
    tenant_id  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    cnp VARCHAR(13),
);
CREATE INDEX IF NOT EXISTS idx_persons_tenant_id ON persons(tenant_id);

CREATE TABLE IF NOT EXISTS projects (
    id INT PRIMARY KEY,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255),
    description TEXT,
    number VARCHAR(50),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    updated_by INT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    county VARCHAR(100),
    city VARCHAR(100),
    street_name VARCHAR(255),
    street_number VARCHAR(10),
    building_entrance VARCHAR(4),
    postal_code VARCHAR(10),
    surface_area DECIMAL(15, 2),
    contract_value DECIMAL(15, 2),
    currency VARCHAR(3),
    payment_terms TEXT,
    planner_id INT NOT NULL REFERENCES legal_entities(id),
    beneficiary_id INT NOT NULL REFERENCES legal_entities(id),
    contractor_id INT NOT NULL REFERENCES legal_entities(id),
    planning_stages VARCHAR(50),  -- semicolon-separated values for simplicity
    verification_domains VARCHAR(200),  -- semicolon-separated values for simplicity
    importance_class VARCHAR(4) CHECK (importance_class IN ('I', 'II', 'III', 'IV')),
    importance_category VARCHAR(1) CHECK (importance_category IN ('A', 'B', 'C', 'D')),
    project_function VARCHAR(50), -- CHECK (project_function IN ('locuire', 'birouri', 'industrie', 'invatamant', 'sanatate', 'cultura', 'sport', 'comercial', 'agricol'))
    report_mentions TEXT
);
CREATE INDEX IF NOT EXISTS idx_projects_tenant_id_project_id ON projects(tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_projects_planner_id ON projects(tenant_id, planner_id);
CREATE INDEX IF NOT EXISTS idx_projects_beneficiary_id ON projects(tenant_id, beneficiary_id);
CREATE INDEX IF NOT EXISTS idx_projects_contractor_id ON projects(tenant_id, contractor_id);
CREATE INDEX IF NOT EXISTS idx_projects_project_function ON projects(tenant_id, project_function);

CREATE TABLE IF NOT EXISTS project_architects (
    project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    architect_id INT NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, architect_id)
);
CREATE INDEX IF NOT EXISTS idx_project_architects_tenant_id_project_id ON project_architects(tenant_id, project_id);

CREATE TABLE IF NOT EXISTS project_payment_stages (
    id INT PRIMARY KEY,
    project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seq_number INT NOT NULL,
    description TEXT,
    date DATE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'payed')),
);
CREATE INDEX IF NOT EXISTS idx_project_payment_stages_tenant_id_project_id ON project_payment_stages(tenant_id, project_id);