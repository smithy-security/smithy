from neo4j import GraphDatabase
import os

# Create a Neo4j driver instance
uri = os.getenv("DATABASE_URI")
print(f"querying endpoint {uri}")
driver = GraphDatabase.driver(uri)

def get_snapshosts_exposed():
    query = """
    MATCH (s:EBSSnapshot)-[:CREATED_FROM]->(v:EBSVolume),
    (v)-[:ATTACHED_TO]->(i:EC2Instance{exposed_internet:true})
    RETURN i.id AS instance_id, v.id AS volume_id, s.id AS snapshot_id, s.lastupdated AS last_updated  LIMIT 25
    """
    with driver.session() as session:
        result = session.run(query)
        snapshots = [
            {
                "instance_id": record["instance_id"], 
                "volume_id": record["volume_id"],
                "snapshot_id": record["snapshot_id"], 
                "last_updated": record["last_updated"],
            } 
        for record in result]
        return snapshots
