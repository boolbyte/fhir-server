/*
 * HAPI FHIR JPA Server - Starter Project
 * S3-compatible binary storage implementation.
 */
package ca.uhn.fhir.jpa.starter.s3;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.jpa.binary.api.StoredDetails;
import ca.uhn.fhir.jpa.binary.svc.BaseBinaryStorageSvcImpl;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException;
import com.google.common.hash.HashingInputStream;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CountingInputStream;
import org.apache.commons.lang3.StringUtils;
import org.hl7.fhir.instance.model.api.IIdType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * S3-compatible binary storage implementation for IBinaryStorageSvc.
 * Works with AWS S3, MinIO, DigitalOcean Spaces, and other S3-compatible object stores.
 */
public class S3BinaryStorageSvcImpl extends BaseBinaryStorageSvcImpl {

	private static final Logger ourLog = LoggerFactory.getLogger(S3BinaryStorageSvcImpl.class);

	private static final String META_HASH = "hash";
	private static final String META_PUBLISHED = "published";
	private static final String META_BYTES = "bytes";

	private final S3Client myS3Client;
	private final String myBucket;

	public S3BinaryStorageSvcImpl(S3Client theS3Client, String theBucket) {
		if (theS3Client == null || StringUtils.isBlank(theBucket)) {
			throw new IllegalArgumentException("S3Client and bucket name are required");
		}
		myS3Client = theS3Client;
		myBucket = theBucket;
	}

	@Override
	public boolean isValidBinaryContentId(String theNewBinaryContentId) {
		return !StringUtils.containsAny(theNewBinaryContentId, '\\', '/', '|', '.');
	}

	@Nonnull
	@Override
	public StoredDetails storeBinaryContent(
			IIdType theResourceId,
			String theBlobIdOrNull,
			String theContentType,
			InputStream theInputStream,
			RequestDetails theRequestDetails)
			throws IOException {

		String id = super.provideIdForNewBinaryContent(theBlobIdOrNull, null, theRequestDetails, theContentType);
		CountingInputStream countingInputStream = createCountingInputStream(theInputStream);
		HashingInputStream hashingInputStream = createHashingInputStream(countingInputStream);

		byte[] data = IOUtils.toByteArray(hashingInputStream);
		long bytes = countingInputStream.getByteCount();
		String hash = hashingInputStream.hash().toString();
		Date published = new Date();

		String key = buildObjectKey(theResourceId, id);
		Map<String, String> metadata = new HashMap<>();
		metadata.put(META_HASH, hash);
		metadata.put(META_PUBLISHED, String.valueOf(published.getTime()));
		metadata.put(META_BYTES, String.valueOf(bytes));

		PutObjectRequest request = PutObjectRequest.builder()
				.bucket(myBucket)
				.key(key)
				.contentType(theContentType != null ? theContentType : "application/octet-stream")
				.metadata(metadata)
				.build();

		myS3Client.putObject(request, RequestBody.fromBytes(data));

		ourLog.info(
				"Stored binary blob with {} bytes and ContentType {} for resource {} in S3 key {}",
				bytes,
				theContentType,
				theResourceId,
				key);

		return new StoredDetails()
				.setBinaryContentId(id)
				.setBytes(bytes)
				.setPublished(published)
				.setHash(hash)
				.setContentType(theContentType);
	}

	@Override
	@Nullable
	public StoredDetails fetchBinaryContentDetails(IIdType theResourceId, String theBlobId) {
		String key = buildObjectKey(theResourceId, theBlobId);
		try {
			var response = myS3Client.headObject(
					HeadObjectRequest.builder().bucket(myBucket).key(key).build());

			Map<String, String> meta = response.metadata() != null ? response.metadata() : new HashMap<>();
			String hash = meta.get(META_HASH);
			String publishedStr = meta.get(META_PUBLISHED);
			String bytesStr = meta.get(META_BYTES);
			long bytes = bytesStr != null ? Long.parseLong(bytesStr) : response.contentLength();
			Date published = publishedStr != null ? new Date(Long.parseLong(publishedStr)) : null;

			return new StoredDetails()
					.setBinaryContentId(theBlobId)
					.setContentType(response.contentType())
					.setHash(hash)
					.setPublished(published)
					.setBytes(bytes);
		} catch (NoSuchKeyException e) {
			return null;
		}
	}

	@Override
	public boolean writeBinaryContent(IIdType theResourceId, String theBlobId, OutputStream theOutputStream)
			throws IOException {
		String key = buildObjectKey(theResourceId, theBlobId);
		try {
			var response = myS3Client.getObject(
					GetObjectRequest.builder().bucket(myBucket).key(key).build());
			try (InputStream inputStream = response) {
				IOUtils.copy(inputStream, theOutputStream);
			}
			return true;
		} catch (NoSuchKeyException e) {
			return false;
		}
	}

	@Override
	public void expungeBinaryContent(IIdType theResourceId, String theBlobId) {
		String key = buildObjectKey(theResourceId, theBlobId);
		try {
			myS3Client.deleteObject(
					DeleteObjectRequest.builder().bucket(myBucket).key(key).build());
			ourLog.info("Expunged binary content for resource {} blob {} from S3 key {}", theResourceId, theBlobId, key);
		} catch (Exception e) {
			ourLog.warn("Failed to delete S3 object {}: {}", key, e.getMessage());
		}
	}

	@Override
	public byte[] fetchBinaryContent(IIdType theResourceId, String theBlobId) throws IOException {
		StoredDetails details = fetchBinaryContentDetails(theResourceId, theBlobId);
		if (details == null) {
			throw new ResourceNotFoundException(
					Msg.code(1327) + "Unknown blob ID: " + theBlobId + " for resource ID " + theResourceId);
		}

		String key = buildObjectKey(theResourceId, theBlobId);
		try {
			var response = myS3Client.getObject(
					GetObjectRequest.builder().bucket(myBucket).key(key).build());
			try (InputStream inputStream = response) {
				return IOUtils.toByteArray(inputStream, details.getBytes());
			}
		} catch (NoSuchKeyException e) {
			throw new ResourceNotFoundException(
					Msg.code(1327) + "Unknown blob ID: " + theBlobId + " for resource ID " + theResourceId);
		}
	}

	private static String buildObjectKey(IIdType theResourceId, String theBlobId) {
		IIdType unqualified = theResourceId.toUnqualifiedVersionless();
		String resourceType = unqualified.getResourceType();
		String idPart = unqualified.getIdPart();
		if (StringUtils.isBlank(resourceType) || StringUtils.isBlank(idPart)) {
			throw new IllegalArgumentException("ResourceId must have resource type and id part");
		}
		return resourceType + "/" + idPart + "/" + theBlobId;
	}
}

