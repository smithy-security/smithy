-- create "finding" table
CREATE TABLE IF NOT EXISTS finding (
   id SERIAL PRIMARY KEY,
   instance_id UUID NOT NULL,
   details JSONB NOT NULL,
   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
