use valence_protocol::nbt::{Compound, List};

pub(super) fn registry_codec() -> Compound {
    let mut codec = Compound::new();
    codec.insert(
        "minecraft:dimension_type",
        registry_container(
            "minecraft:dimension_type",
            vec![registry_entry(
                "minecraft:overworld",
                0,
                overworld_dimension(),
            )],
        ),
    );
    codec.insert(
        "minecraft:worldgen/biome",
        registry_container(
            "minecraft:worldgen/biome",
            vec![registry_entry("minecraft:plains", 1, plains_biome())],
        ),
    );
    codec
}

fn registry_container(kind: &str, values: Vec<Compound>) -> Compound {
    let mut compound = Compound::new();
    compound.insert("type", kind.to_owned());
    compound.insert("value", List::Compound(values));
    compound
}

fn registry_entry(name: &str, id: i32, element: Compound) -> Compound {
    let mut entry = Compound::new();
    entry.insert("name", name.to_owned());
    entry.insert("id", id);
    entry.insert("element", element);
    entry
}

fn overworld_dimension() -> Compound {
    let mut spawn_light_value = Compound::new();
    spawn_light_value.insert("min_inclusive", 0);
    spawn_light_value.insert("max_inclusive", 7);

    let mut spawn_light = Compound::new();
    spawn_light.insert("type", "minecraft:uniform".to_owned());
    spawn_light.insert("value", spawn_light_value);

    let mut dimension = Compound::new();
    dimension.insert("piglin_safe", false);
    dimension.insert("has_raids", true);
    dimension.insert("monster_spawn_light_level", spawn_light);
    dimension.insert("monster_spawn_block_light_limit", 0);
    dimension.insert("natural", true);
    dimension.insert("ambient_light", 0.0_f32);
    dimension.insert("infiniburn", "#minecraft:infiniburn_overworld".to_owned());
    dimension.insert("respawn_anchor_works", false);
    dimension.insert("has_skylight", true);
    dimension.insert("bed_works", true);
    dimension.insert("effects", "minecraft:overworld".to_owned());
    dimension.insert("min_y", -64);
    dimension.insert("height", 384);
    dimension.insert("logical_height", 384);
    dimension.insert("coordinate_scale", 1.0_f64);
    dimension.insert("ultrawarm", false);
    dimension.insert("has_ceiling", false);
    dimension
}

fn plains_biome() -> Compound {
    let mut mood_sound = Compound::new();
    mood_sound.insert("sound", "minecraft:ambient.cave".to_owned());
    mood_sound.insert("tick_delay", 6000);
    mood_sound.insert("block_search_extent", 8);
    mood_sound.insert("offset", 2.0_f64);

    let mut effects = Compound::new();
    effects.insert("sky_color", 7907327);
    effects.insert("water_fog_color", 329011);
    effects.insert("fog_color", 12638463);
    effects.insert("water_color", 4159204);
    effects.insert("mood_sound", mood_sound);

    let mut biome = Compound::new();
    biome.insert("precipitation", "rain".to_owned());
    biome.insert("temperature", 0.8_f32);
    biome.insert("downfall", 0.4_f32);
    biome.insert("effects", effects);
    biome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_codec_contains_overworld_dimension_and_plains_biome() {
        let codec = registry_codec();

        assert!(codec.contains_key("minecraft:dimension_type"));
        assert!(codec.contains_key("minecraft:worldgen/biome"));
    }
}
