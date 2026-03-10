// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! File-based streaming decryption functionality.

use crate::{
    decrypt_chunk, EncryptedChunk, Result, STREAM_DECRYPT_BATCH_SIZE,
};
use bytes::Bytes;
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
};
use xor_name::XorName;

/// Decrypts data from storage using streaming approach, processing chunks in batches
/// to minimize memory usage.
///
/// This function implements true streaming by:
/// 1. Processing chunks in ordered batches
/// 2. Fetching one batch at a time
/// 3. Decrypting and writing each batch immediately to disk
/// 4. Continuing until all chunks are processed
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information
/// * `output_filepath` - The path to write the decrypted data to
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given a list of XorName hashes
///
/// # Returns
///
/// * `Result<()>` - An empty result or an error if decryption fails
pub fn streaming_decrypt_from_storage<F>(
    data_map: &crate::DataMap,
    output_filepath: &Path,
    get_chunk_parallel: F,
) -> Result<()>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    let root_map = if data_map.is_child() {
        crate::get_root_data_map_parallel(data_map.clone(), &get_chunk_parallel)?
    } else {
        data_map.clone()
    };

    // Get all chunk information and source hashes
    let mut chunk_infos = root_map.infos().to_vec();
    // Sort chunks by index to ensure proper order during processing
    chunk_infos.sort_by_key(|info| info.index);
    let src_hashes = crate::extract_hashes(&root_map);

    let mut has_initialized_file = false;

    for batch_start in (0..chunk_infos.len()).step_by(*STREAM_DECRYPT_BATCH_SIZE) {
        let batch_end = (batch_start + *STREAM_DECRYPT_BATCH_SIZE).min(chunk_infos.len());
        let batch_infos = &chunk_infos[batch_start..batch_end];

        // Extract chunk hashes for this batch
        let batch_hashes: Vec<_> = batch_infos
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .collect();

        // Fetch only the chunks for this batch
        let mut fetched_chunks = get_chunk_parallel(&batch_hashes)?;
        // Shall be ordered to allow sequential appended to file
        fetched_chunks.sort_by_key(|(index, _content)| *index);

        let batch_chunks = fetched_chunks
            .into_iter()
            .map(|(_index, content)| EncryptedChunk { content })
            .collect::<Vec<_>>();

        // Process and write this batch immediately to disk
        let mut batch_file = if !has_initialized_file {
            has_initialized_file = true;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(output_filepath)?
        } else {
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(output_filepath)?
        };

        for (info, chunk) in batch_infos.iter().zip(batch_chunks.iter()) {
            let decrypted_chunk = decrypt_chunk(info.index, &chunk.content, &src_hashes)?;

            batch_file.write_all(&decrypted_chunk)?;
        }

        batch_file.sync_all()?;
    }

    Ok(())
}
