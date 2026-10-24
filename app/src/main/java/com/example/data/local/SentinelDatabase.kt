package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.data.model.ApprovedScopeEntity
import com.example.data.model.AssessmentJobEntity
import com.example.data.model.AuditAction
import com.example.data.model.AuditLogEntity
import com.example.data.model.AuthorizationRecordEntity
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
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class SentinelDatabase : RoomDatabase() {
    abstract fun sentinelDao(): SentinelDao

    companion object {
        @Volatile
        private var INSTANCE: SentinelDatabase? = null

        fun getDatabase(context: Context): SentinelDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    SentinelDatabase::class.java,
                    "sentinel_security_db"
                )
                    .addCallback(SentinelDatabaseCallback())
                    .fallbackToDestructiveMigration()
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
            val defaultClientId = "client-acme-corp-01"
            val defaultEngagementId = "eng-2026-acme-posture"

            // 1. Initial Client
            dao.insertClient(
                ClientEntity(
                    id = defaultClientId,
                    name = "Acme Technologies Global",
                    organization = "Acme Cyber Ops & Cloud Division",
                    contactEmail = "security@acme-corp.internal",
                    createdAt = System.currentTimeMillis() - 86400000L * 30
                )
            )

            // 2. Initial Active Engagement
            dao.insertEngagement(
                EngagementEntity(
                    id = defaultEngagementId,
                    clientId = defaultClientId,
                    title = "External Perimeter & Web Posture Audit (Q4)",
                    engagementType = "Defensive Web Security Assessment",
                    leadAssessor = "Senior Security Engineer (CISSP/OSCP)",
                    status = EngagementStatus.ACTIVE,
                    targetEnvironment = "Production / Public Surface (Non-Destructive)",
                    startDate = System.currentTimeMillis() - 86400000L * 14,
                    endDate = System.currentTimeMillis() + 86400000L * 45
                )
            )

            // 3. Signed Written Authorization Record (ROA)
            dao.insertAuthorization(
                AuthorizationRecordEntity(
                    id = "auth-roa-2026-902",
                    engagementId = defaultEngagementId,
                    authorizedByName = "David Vance, CISO",
                    authorizedByRole = "Chief Information Security Officer",
                    authorizedByEmail = "ciso@acme-corp.internal",
                    documentReference = "ROA-SIGNED-SOW-2026-0492.PDF",
                    authorizationScopeSummary = "Authorization granted for defensive TLS, DNS, HTTP headers, and configuration audit of public assets scanme.nmap.org and example.com. Non-destructive only.",
                    validFromTimestamp = System.currentTimeMillis() - 86400000L * 14,
                    validToTimestamp = System.currentTimeMillis() + 86400000L * 45,
                    explicitTestingPermitted = true,
                    emergencyContactPhone = "+1-555-019-8234",
                    signedAtTimestamp = System.currentTimeMillis() - 86400000L * 14,
                    rulesOfEngagementNotes = "Strict scope limits: Non-destructive checks only. Prohibited: denial-of-service, automated credential stuffing, intrusive brute force."
                )
            )

            // 4. Approved Scopes (Pre-approved test domains)
            dao.insertScope(
                ApprovedScopeEntity(
                    id = "scope-01",
                    engagementId = defaultEngagementId,
                    hostname = "scanme.nmap.org",
                    wildcardAllowed = false,
                    allowedPorts = "80,443",
                    pathPrefix = "/",
                    active = true
                )
            )
            dao.insertScope(
                ApprovedScopeEntity(
                    id = "scope-02",
                    engagementId = defaultEngagementId,
                    hostname = "example.com",
                    wildcardAllowed = true,
                    allowedPorts = "80,443",
                    pathPrefix = "/",
                    active = true
                )
            )

            // 5. Initial Audit Log
            dao.insertAuditLog(
                AuditLogEntity(
                    action = AuditAction.AUTHORIZATION_SIGNED,
                    actor = "David Vance (CISO)",
                    target = "Engagement eng-2026-acme-posture",
                    details = "Written Authorization Record signed with document reference ROA-SIGNED-SOW-2026-0492.PDF. Scope: scanme.nmap.org, example.com",
                    hashSignature = "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
                )
            )
            dao.insertAuditLog(
                AuditLogEntity(
                    action = AuditAction.SCOPE_ADDED,
                    actor = "Senior Security Engineer",
                    target = "scanme.nmap.org, example.com",
                    details = "Approved targets locked into active scope enforcement registry with port restrictions [80, 443].",
                    hashSignature = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                )
            )
        }
    }
}
