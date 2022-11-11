import { X509Certificate } from "./x509_cert";
import { ICertificateStorage, ICertificateStorageHandler } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./certificate_storage_handler";

export class X509ChainValidator implements ICertificateStorage {
  public certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();

  // verify(certificate: X509Certificate);
}

