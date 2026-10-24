package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditAction
import com.example.data.model.AuditLogEntity
import com.example.data.model.AuthorizationRecordEntity
import com.example.data.model.AuthorizationStatus
import com.example.data.model.ClientEntity
import com.example.data.model.EngagementEntity
import com.example.data.model.EngagementStatus
import com.example.data.model.SecurityFindingEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Database(
    entities = [
        ClientEntity::class,
        EngagementEntity::class,
        AuthorizationRecordEntity::class,
        ApprovedScopeEntity::class,
        AssessmentJobEntity::class,
        SecurityFindingEntity::class,
        AuditLogEntity::class
    ],
    version = 2,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class SentinelDatabase : RoomDatabase() {
    abstract fun sentinelDao(): SentinelDao

    companion object {
        @Volatile
        private var INSTANCE: SentinelDatabase? = null

        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // clients
                db.execSQL("ALTER TABLE clients ADD COLUMN isDemo INTEGER NOT NULL DEFAULT 0")
                // engagements
                db.execSQL("ALTER TABLE engagements ADD COLUMN isDemo INTEGER NOT NULL DEFAULT 0")
                // authorizations
                db.execSQL("ALTER TABLE authorizations ADD COLUMN evidenceHash TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE authorizations ADD COLUMN verificationStatus TEXT NOT NULL DEFAULT 'PENDING_VERIFICATION'")
                db.execSQL("ALTER TABLE authorizations ADD COLUMN verifiedBy TEXT DEFAULT NULL")
                db.execSQL("ALTER TABLE authorizations ADD COLUMN verifiedAtTimestamp INTEGER DEFAULT NULL")
                db.execSQL("ALTER TABLE authorizations ADD COLUMN isDemo INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE authorizations ADD COLUMN revokedAtTimestamp INTEGER DEFAULT NULL")
                db.execSQL("ALTER TABLE authorizations ADD COLUMN revocationReason TEXT DEFAULT NULL")
                // approved_scopes
                db.execSQL("ALTER TABLE approved_scopes ADD COLUMN isDemo INTEGER NOT NULL DEFAULT 0")
                // assessment_jobs
                db.execSQL("ALTER TABLE assessment_jobs ADD COLUMN checksPassedCount INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE assessment_jobs ADD COLUMN checksFailedCount INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE assessment_jobs ADD COLUMN isDemo INTEGER NOT NULL DEFAULT 0")
                // security_findings
                db.execSQL("ALTER TABLE security_findings ADD COLUMN verifiedBy TEXT DEFAULT NULL")
                db.execSQL("ALTER TABLE security_findings ADD COLUMN verifiedAtTimestamp INTEGER DEFAULT NULL")
                // audit_logs
                db.execSQL("ALTER TABLE audit_logs ADD COLUMN previousHash TEXT NOT NULL DEFAULT 'GENESIS'")
            }
        }

        fun getDatabase(context: Context): SentinelDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    SentinelDatabase::class.java,
                    "sentinel_security_db"
                )
                    .addMigrations(MIGRATION_1_2)
                    .addCallback(SentinelDatabaseCallback())
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }

    private class SentinelDatabaseCallback : Callback() {
        override fun onCreate(db: SupportSQLiteDatabase) {
            super.onCreate(db)
            INSTANCE?.let { database ->
                CoroutineScope(Dispatchers.IO).launch {
                    populateInitialData(database.sentinelDao())
                }
            }
        }

        private suspend fun populateInitialData(dao: SentinelDao) {
            val demoClientId = "demo-client-acme-corp"
            val demoEngagementId = "demo-eng-2026-sample"

            // 1. Initial Sample Client (Segregated as Demo)
            dao.insertClient(
                ClientEntity(
                    id = demoClientId,
                    name = "Acme Technologies (Sample Client)",
                    organization = "Acme Cyber Ops [DEMO ENVIRONMENT]",
                    contactEmail = "demo-secops@acme-sample.internal",
                    isDemo = true,
                    createdAt = System.currentTimeMillis() - 86400000L * 30
                )
            )

            // 2. Initial Sample Engagement (Marked as Demo)
            dao.insertEngagement(
                EngagementEntity(
                    id = demoEngagementId,
                    clientId = demoClientId,
                    title = "[DEMO] Perimeter Web Posture Review",
                    engagementType = "Defensive Web Security Assessment",
                    leadAssessor = "Auditor (Demo Role)",
                    status = EngagementStatus.DRAFT,
                    targetEnvironment = "Synthetic / Isolated Test Specimen Only",
                    startDate = System.currentTimeMillis() - 86400000L * 14,
                    endDate = System.currentTimeMillis() + 86400000L * 45,
                    isDemo = true
                )
            )

            // 3. Unverified Sample ROA (explicitTestingPermitted = FALSE, Status = PENDING_VERIFICATION)
            // Demonstrates that demo data NEVER bypasses authorization gates.
            dao.insertAuthorization(
                AuthorizationRecordEntity(
                    id = "auth-demo-sample-01",
                    engagementId = demoEngagementId,
                    authorizedByName = "Sample Officer (Unverified)",
                    authorizedByRole = "Demo Role",
                    authorizedByEmail = "demo-secops@acme-sample.internal",
                    documentReference = "SAMPLE-DRAFT-ROA.PDF",
                    evidenceHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    verificationStatus = AuthorizationStatus.PENDING_VERIFICATION,
                    verifiedBy = null,
                    verifiedAtTimestamp = null,
                    authorizationScopeSummary = "Demo scope documentation only. Not verified for active scanning.",
                    validFromTimestamp = System.currentTimeMillis() - 86400000L * 14,
                    validToTimestamp = System.currentTimeMillis() + 86400000L * 45,
                    explicitTestingPermitted = false, // Must remain false!
                    emergencyContactPhone = "+1-555-0100",
                    signedAtTimestamp = System.currentTimeMillis() - 86400000L * 14,
                    rulesOfEngagementNotes = "Sample record for demonstration. Requires auditor verification before assessment can proceed.",
                    isDemo = true
                )
            )

            // 4. Sample Scopes
            dao.insertScope(
                ApprovedScopeEntity(
                    id = "demo-scope-01",
                    engagementId = demoEngagementId,
                    hostname = "scanme.nmap.org",
                    wildcardAllowed = false,
                    allowedPorts = "80,443",
                    pathPrefix = "/",
                    active = true,
                    isDemo = true
                )
            )

            // 5. Initial Genesis Audit Log
            val genesisHash = "GENESIS_SENTINEL_ROOT_00000000000000000000000000000000"
            val now = System.currentTimeMillis()
            val payload = "GENESIS|$now|System Initialize|${AuditAction.ENGAGEMENT_CREATED.name}|demo-eng-2026-sample|Database initialized with safe demo specimen"
            val signature = "sha256:" + java.security.MessageDigest.getInstance("SHA-256")
                .digest(payload.toByteArray())
                .joinToString("") { "%02x".format(it) }

            dao.insertAuditLog(
                AuditLogEntity(
                    timestamp = now,
                    actor = "System Initialize",
                    action = AuditAction.ENGAGEMENT_CREATED,
                    target = "demo-eng-2026-sample",
                    details = "Database initialized with safe demo specimen. Live testing disabled pending written verification.",
                    previousHash = genesisHash,
                    hashSignature = signature
                )
            )
        }
    }
}
